"""Slack admin metadata: apps and the tokens their scopes imply; never a token value or a webhook URL."""

API_ORIGIN = "https://slack.com"
AUDIT_ORIGIN = "https://api.slack.com"
CONTRACT_VERSION = "slack-admin-metadata-v1"
# In order: the audit log first (optional), so the approved apps can take its installs; then the apps
# the audit log shows installed that the approved list does not name.
SOURCES = ("audit_events", "approved_apps", "installed_apps")
# The audit log's app lifecycle actions (Audit Logs API, "App" actions).
AUDIT_ACTIONS = ("app_installed", "app_uninstalled", "app_scopes_expanded", "app_token_preserved",
                 "bot_token_upgraded", "bot_token_downgraded", "org_app_workspace_added",
                 "org_app_workspace_removed")
INSTALLS = ("app_installed", "org_app_workspace_added")
REMOVALS = ("app_uninstalled", "org_app_workspace_removed")
