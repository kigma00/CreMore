"""Provider-owned onboarding metadata; importing it performs no collection."""

# Organization-installation permission per read (task kind). Enterprise reads use
# the Enterprise installation, and its audit log a classic PAT, so they are not here.
SOURCE_PERMISSIONS = {
    "org_sso": {"organization_administration": "read"},
    "org_fgpat": {"organization_personal_access_tokens": "read"},
    "org_fgpat_repositories": {"organization_personal_access_tokens": "read"},
    "org_pat_requests": {"organization_personal_access_token_requests": "read"},
    "org_pat_request_repositories": {"organization_personal_access_token_requests": "read"},
    "org_installations": {"organization_administration": "read"},
    "org_repositories": {"metadata": "read"},
    "org_workflow_policy": {"organization_administration": "read"},
    "repo_deploy_keys": {"administration": "read"},
    "repo_workflow_policy": {"administration": "read"},
    "repo_actions_policy": {"administration": "read"},
    "repo_fork_policy": {"administration": "read"},
    "repo_actions_runs": {"actions": "read"},
    "run_jobs": {"actions": "read"},
    "org_actions_secrets": {"organization_secrets": "read"},
    "org_secret_repositories": {"organization_secrets": "read"},
    "repo_actions_secrets": {"secrets": "read"},
    "repo_environments": {"actions": "read"},
    "environment_actions_secrets": {"environments": "read"},
    "org_audit": {"organization_administration": "read"},
}

DESCRIPTOR = {
    "provider": "github",
    # Export-local row locators are observations, never unique inventory identities.
    "snapshot_identity_prefixes": ["inventory:export:"],
    "label": "GitHub",
    "purpose": ["issuer_inventory", "usage", "vault_metadata"],
    "editions": ["cloud", "enterprise_cloud", "enterprise_server", "dedicated"],
    "origins": ["https://github.com"],
    "origin_hint": "https://ghes.example.com",
    "auth_types": ["github_app"],
    "auth_secret_roles": {"github_app": ["app_id", "private_key", "installation_id", "audit_token"]},
    # Roles a run can do without. The classic PAT only the Enterprise audit reads use: if it
    # cannot be resolved, those reads fail (GITHUB_ENTERPRISE_AUDIT_TOKEN_UNAVAILABLE), not the
    # whole run. installation_id: collection looks up each organization's installation instead.
    "optional_secret_roles": ["installation_id", "audit_token"],
    "scope_kinds": ["organization", "enterprise"],
    "capabilities": ["inventory", "audit", "relations", "policy", "public_keys", "vault_metadata", "issuer_digest"],
    "modes": ["organization", "enterprise"],
    "options": ["sources", "include_actions", "include_audit_events",
                "audit_created_after", "audit_lookback_days", "max_targets", "include_provider_hashes",
                "actions_run_days", "audit_scope", "enterprise_only", "github_inventory", "run_time_limit_minutes"],
    "defaults": {"options": {"mode": "organization"}},
    "source_options": [
        {"value": "org_sso", "label": "SSO credential authorizations", "label_ko": "SSO 자격증명 승인"},
        {"value": "org_fgpat", "label": "Fine-grained PAT grants", "label_ko": "세분화 PAT 승인"},
        {"value": "org_pat_requests", "label": "PAT requests", "label_ko": "PAT 승인 요청"},
        {"value": "org_installations", "label": "App installations", "label_ko": "앱 설치"},
        {"value": "org_repositories", "label": "Repositories and policies", "label_ko": "저장소·정책"},
        {"value": "org_workflow_policy", "label": "Organization workflow policy", "label_ko": "조직 워크플로 정책"},
        {"value": "enterprise_org_installations", "label": "Enterprise App installations", "label_ko": "기업 앱 설치"},
        {"value": "enterprise_org_repositories", "label": "Enterprise repositories", "label_ko": "기업 저장소"},
        {"value": "repo_actions_runs", "label": "Actions run context", "label_ko": "Actions 실행 정보"},
        {"value": "org_actions_secrets", "requires_capability": "vault_metadata", "label": "Organization secret metadata", "label_ko": "조직 시크릿 메타데이터"},
        {"value": "repo_actions_secrets", "requires_capability": "vault_metadata", "label": "Repository secret metadata", "label_ko": "저장소 시크릿 메타데이터"},
        {"value": "environment_actions_secrets", "requires_capability": "vault_metadata", "label": "Environment secret metadata", "label_ko": "환경 시크릿 메타데이터"},
    ],
    # The organization-installation permission each read needs (the onboarding table).
    "source_permissions": SOURCE_PERMISSIONS,
    # Recollection is only the installation check: plan_recollection refuses every other retry.
    "native_export": True, "compare": False, "recollect": True,
    "limitations": [
        "SSO_AUTHORIZATIONS_ARE_NOT_EVERY_TOKEN_A_MEMBER_HOLDS",
        "ENTERPRISE_CREDENTIALS_RESPONSES_CARRY_NO_TOTAL_COUNT",
        "AN_ENTERPRISE_INSTALLATION_TOKEN_HAS_NO_REPOSITORY_ACCESS",
        "GHES_MANAGEMENT_ENDPOINTS_VARY_BY_SERVER_VERSION",
        "ENTERPRISE_AUDIT_LOG_ACCEPTS_ONLY_A_CLASSIC_PAT_WITH_READ_AUDIT_LOG",
        "ACTIONS_SECRET_VALUES_AND_ENCRYPTED_VALUES_ARE_NOT_RETURNED",
        "ACTIONS_METADATA_DOES_NOT_ESTABLISH_VALUE_EQUALITY",
        "PROVIDER_DIGEST_REQUIRES_ENTERPRISE_MODE_AND_EXPLICIT_OPT_IN",
        "PROVIDER_DIGEST_IS_NOT_THE_CREDENTIAL_HMAC_SCHEME",
    ],
}
