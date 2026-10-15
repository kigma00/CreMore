"""notion connection identity check using the configured scanner credential."""
from __future__ import annotations

from cremore.collectors.base import error_label
from cremore.collectors.credential_result import ACTIVE, INDETERMINATE, REJECTED, CredentialCheck
from cremore.http_client import bounded_request
from cremore_notion_provider.collectors.requests import connection_limiter, paced


def check_notion(client, token: str, base_url: str = "https://api.notion.com",
                 notion_version: str = "2022-06-28") -> CredentialCheck:
    if not token:
        return CredentialCheck(INDETERMINATE, error="NO_CREDENTIAL")
    headers = {"Authorization": f"Bearer {token}", "Notion-Version": notion_version}
    base = base_url.rstrip("/")
    try:
        # The connection's limiter: a check during a scan of the same token waits its turn.
        resp = paced(connection_limiter(token, base),
                     lambda: bounded_request(client, "GET", base + "/v1/users/me", headers=headers))
    except Exception as exc:  # noqa: BLE001 -- Provider failures yield a safe status/code, never credential-bearing exception text.
        return CredentialCheck(INDETERMINATE, error=error_label(exc))
    status = getattr(resp, "status_code", 0)
    if status == 401:
        return CredentialCheck(REJECTED, error="HTTP 401")
    if status != 200:
        return CredentialCheck(INDETERMINATE, error=f"HTTP {status}")
    try:
        body = resp.json()
    except Exception as exc:  # noqa: BLE001 -- Provider failures yield a safe status/code, never credential-bearing exception text.
        return CredentialCheck(INDETERMINATE, error=error_label(exc))
    if not isinstance(body, dict):
        return CredentialCheck(INDETERMINATE, error="MALFORMED_RESPONSE")
    bot = body.get("bot") or {}
    workspace = str(bot.get("workspace_name") or "") if isinstance(bot, dict) else ""
    return CredentialCheck(ACTIVE, owner=str(body.get("name") or body.get("id") or ""), workspace=workspace)
