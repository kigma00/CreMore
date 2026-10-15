"""Exact SDK-operation boundary for scanner identities, never remediation."""

from __future__ import annotations

READ_OPERATIONS = {
    "s3": frozenset({
        "list_buckets", "head_bucket", "get_bucket_location", "list_objects_v2",
        "list_object_versions", "get_object", "head_object", "get_object_tagging",
        "get_bucket_versioning", "get_bucket_tagging", "get_bucket_policy_status",
        "get_public_access_block",
        "get_bucket_policy", "get_bucket_acl", "get_object_acl",
    }),
    "iam": frozenset({
        "get_access_key_last_used", "list_access_keys", "get_user", "list_user_tags",
        "list_users", "generate_credential_report", "get_credential_report", "list_service_specific_credentials",
        "simulate_principal_policy", "get_role",
        # identity policy documents (cremore_aws_provider.investigation.identity_policies)
        "list_user_policies", "get_user_policy", "list_attached_user_policies", "list_groups_for_user",
        "list_group_policies", "get_group_policy", "list_attached_group_policies", "list_role_policies",
        "get_role_policy", "list_attached_role_policies", "get_policy", "get_policy_version",
    }),
    "sts": frozenset({"assume_role", "get_caller_identity"}),
    # IAM Identity Center assignment discovery and credential vending. Like
    # sts:assume_role above, get_role_credentials mints a session rather than
    # reading data; it changes nothing in the account it names.
    "sso": frozenset({"list_accounts", "list_account_roles", "get_role_credentials"}),
    "cloudtrail": frozenset({"lookup_events", "start_query", "get_query_results"}),
    "ec2": frozenset({"describe_regions"}),
    "secretsmanager": frozenset({
        "list_secrets", "describe_secret", "list_secret_version_ids", "get_resource_policy",
    }),
    "ssm": frozenset({"describe_parameters"}),
    # get_key_policy: whether a key's policy lets IAM policies grant its use (investigation/potential_access.py).
    "kms": frozenset({"decrypt", "get_key_policy"}),
    # Read-only account discovery from a delegated-administrator account.
    "organizations": frozenset({
        "list_accounts", "describe_account",
        "list_accounts_for_parent", "list_organizational_units_for_parent", "list_roots", "describe_organization",
    }),
    "controltower": frozenset({"list_baselines", "list_enabled_baselines", "get_enabled_baseline"}),
}


# Only the opt-in server collection of an approved AWS secret store uses this
# set; scanner sessions keep READ_OPERATIONS and can never read a value. A
# value-reader session (aws_sessions.VALUE_READER_ROLE) makes no other client.
VAULT_OPERATIONS = {
    "secretsmanager": READ_OPERATIONS["secretsmanager"] | {"get_secret_value"},
    "ssm": frozenset({"get_parameters_by_path"}),
}


class ReadOnlyViolation(PermissionError):
    pass


class ReadOnlyClient:
    def __init__(self, client, service: str, operations=READ_OPERATIONS) -> None:
        if service not in operations:
            raise ValueError("unsupported scanner AWS service")
        self._client = client
        self.service = service
        self._allowed = operations[service]

    def _check(self, operation: str) -> None:
        if operation not in self._allowed:
            raise ReadOnlyViolation(f"scanner operation denied: {self.service}.{operation}")

    def __getattr__(self, operation: str):
        self._check(operation)
        return getattr(self._client, operation)

    def get_paginator(self, operation: str):
        self._check(operation)
        return self._client.get_paginator(operation)

    def can_paginate(self, operation: str) -> bool:
        self._check(operation)
        return self._client.can_paginate(operation)


def readonly_client(client, service: str, operations=READ_OPERATIONS) -> ReadOnlyClient:
    if isinstance(client, ReadOnlyClient):
        if client.service != service or client._allowed != operations.get(service):
            raise ValueError("scanner AWS service mismatch")
        return client
    return ReadOnlyClient(client, service, operations)
