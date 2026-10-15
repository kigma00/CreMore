"""Authenticated Azure tenant and ARM resource lists; never secret values."""

from cremore.onboarding.probe import json_body, probe
from cremore_azure_provider.arm import STORAGE_VERSION, VAULT_VERSION
from cremore_azure_provider.arm.transport import STORAGE_ID, VAULT_ID, page_query


def auth_context(provider, edition, values):
    from cremore_azure_provider.onboarding import _guid, target

    if provider == "azure_devops":
        return target(provider, edition, values)
    return {"tenant": _guid(values.get("tenant"), "AZURE_TENANT_ID_INVALID")}


def authenticate(connection, secrets, context):
    from cremore_azure_provider.onboarding import GRAPH, _bearer

    if connection["provider"] == "azure_devops":
        from cremore_azure_provider.onboarding_devops_discovery import (
            authenticate as devops_authenticate,
        )

        return devops_authenticate(connection, secrets, context)
    _bearer(connection, secrets, GRAPH + "/.default", context)
    return {"status": "GRANTED", "subject": connection["target"]["tenant"]}


def _list(connection, secrets, context, path, version, subscription=""):
    from cremore_azure_provider.onboarding import ARM, OnboardingValueError, _bearer

    headers = _bearer(connection, secrets, ARM + "/.default", context)
    query, items, seen = {"path": path, "params": {"api-version": version}}, [], set()
    with context.http_client() as client:
        for _page in range(100):
            response = probe(client, "GET", ARM + query["path"], params=query["params"], headers=headers)
            if response[0] != "GRANTED":
                raise OnboardingValueError("AZURE_TARGET_LIST_ACCESS_DENIED" if response[0] == "MISSING" else response[1] or "REQUEST_FAILED")
            body = json_body(response[2])
            rows = body.get("value") if isinstance(body, dict) else None
            if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
                raise OnboardingValueError("MALFORMED_RESPONSE")
            items.extend(rows)
            if len(items) > 10000:
                raise OnboardingValueError("ONBOARDING_TARGET_LIMIT")
            query = page_query(body.get("nextLink"), path=path, subscription=subscription, vaults="KeyVault" in path)
            if not query:
                return items
            cursor = query["params"]["$skiptoken"]
            if cursor in seen:
                raise OnboardingValueError("PAGINATION_INVALID")
            seen.add(cursor)
    raise OnboardingValueError("ONBOARDING_TARGET_LIMIT")


def discover(connection, secrets, context):
    from cremore_azure_provider.onboarding import OnboardingValueError, _guid

    if connection["provider"] == "azure_devops":
        from cremore_azure_provider.onboarding_devops_discovery import discover as devops_discover

        return devops_discover(connection, secrets, context)
    tenant, purposes = connection["target"]["tenant"], connection["purposes"]
    roots = []
    if "identity" in purposes:
        roots.append({"label": "Entra ID · " + tenant, "target": {"tenant": tenant}, "purposes": ["identity"]})
    if not set(purposes) - {"identity"}:
        return roots, "COMPLETE"
    subscriptions = _list(connection, secrets, context, "/subscriptions", "2022-12-01")
    visible = 0
    for row in subscriptions:
        if str(row.get("tenantId", "")).lower() != tenant or row.get("state") != "Enabled":
            continue
        subscription = _guid(row.get("subscriptionId"), "AZURE_SUBSCRIPTION_ID_INVALID")
        visible += 1
        base = {"tenant": tenant, "subscription": subscription}
        path = f"/subscriptions/{subscription}/providers/"
        storage = _list(connection, secrets, context, path + "Microsoft.Storage/storageAccounts", STORAGE_VERSION, subscription) if set(purposes) & {"exposure", "inventory"} else []
        for resource in storage:
            ident = resource.get("id", "")
            if not isinstance(ident, str) or not STORAGE_ID.fullmatch(ident) or ident.split("/")[2].lower() != subscription:
                raise OnboardingValueError("MALFORMED_RESPONSE")
        if "inventory" in purposes:
            roots.append({"label": "Azure · " + str(row.get("displayName") or subscription), "target": base,
                "purposes": ["inventory"], "plan_options": {"storage_key_accounts": [r["id"] for r in storage]}})
        if "exposure" in purposes:
            roots.extend({"label": "Storage · " + r["id"].rsplit("/", 1)[1], "target": {**base,
                          "storage_account": r["id"].rsplit("/", 1)[1]}, "purposes": ["exposure"]} for r in storage)
        if "vault" in purposes:
            for vault in _list(connection, secrets, context, path + "Microsoft.KeyVault/vaults", VAULT_VERSION, subscription):
                ident = vault.get("id", "")
                if not isinstance(ident, str) or not VAULT_ID.fullmatch(ident) or ident.split("/")[2].lower() != subscription:
                    raise OnboardingValueError("MALFORMED_RESPONSE")
                name = ident.rsplit("/", 1)[1]
                roots.append({"label": "Key Vault · " + name, "target": {**base, "key_vaults": [name]}, "purposes": ["vault"]})
    if "inventory" in purposes and not visible:
        # An Entra-only identity may have no ARM subscriptions. This says
        # nothing about ARM access; Graph permissions are checked separately.
        existing = next((r for r in roots if r["target"] == {"tenant": tenant}), None)
        if existing:
            existing["purposes"].append("inventory")
        else:
            roots.append({"label": "Entra ID · " + tenant, "target": {"tenant": tenant}, "purposes": ["inventory"]})
    return roots, "COMPLETE"
