"""ARM metadata discovery never grants secret access to discovered resources."""

DESCRIPTOR = {
    "provider": "azure_resource_manager", "label": "Azure Resource Manager",
    "purpose": ["issuer_inventory"], "editions": ["cloud"],
    "origins": ["https://management.azure.com"], "origin_hint": "https://management.azure.com",
    "auth_types": ["workload_identity", "private_key_jwt"],
    "auth_secret_roles": {"workload_identity": [], "private_key_jwt": ["client_id", "private_key", "tenant_id"]},
    "scope_kinds": ["organization", "subscription"], "capabilities": ["inventory", "issuer_value"],
    "modes": ["inventory", "discovery"],
    "options": ["sources", "include_values", "azure_storage_accounts"],
    "defaults": {"options": {"sources": ["vaults", "storage_accounts"]}},
    "source_options": [
        {"value": "subscriptions", "label": "Visible subscriptions", "label_ko": "접근 가능한 구독"},
        {"value": "vaults", "label": "Vault metadata", "label_ko": "금고 메타데이터"},
        {"value": "storage_accounts", "label": "Storage account metadata", "label_ko": "Storage 계정 메타데이터"},
        {"value": "storage_keys", "label": "Approved Storage key fingerprints",
         "label_ko": "승인된 Storage 키 지문", "requires_capability": "issuer_value"},
    ],
    "native_export": True, "compare": False, "recollect": False,
    "limitations": [
        "DISCOVERY_DOES_NOT_GRANT_RESOURCE_OR_SECRET_ACCESS",
        "STORAGE_KEYS_REQUIRE_EXPLICIT_ACCOUNT_IDS_INCLUDE_VALUES_AND_LISTKEYS_ACTION",
        "SAS_TOKENS_HAVE_NO_COMPLETE_PROVIDER_ISSUANCE_LIST",
        "ACCOUNT_KEY_READ_IS_NOT_A_SERVICE_PERMISSION_TEST",
        "SUBSCRIPTION_DISCOVERY_IS_VISIBLE_TENANT_METADATA_ONLY",
        "PUBLIC_AZURE_RESOURCE_MANAGER_ORIGIN_ONLY",
    ],
}
