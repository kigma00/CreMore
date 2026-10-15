"""Enterprise preflight without creating an export or consuming its allowance."""

from cremore.coverage.metadata_models import MetadataOptions
from cremore.onboarding.probe import item, probe
from cremore_github_provider.github_hosts import api_base, web_base
from cremore_github_provider.metadata import API_VERSION
from cremore_github_provider.metadata.http import Budget, SourceError, TokenBroker, Transport


def inventory_access(connection, envelope, context):
    enterprise = connection["target"]["enterprise"]
    result = {"permission": "enterprise_credentials_read", "subject": enterprise}
    # The published Export API contract is Enterprise Cloud (including GHE.com).
    # Do not turn an arbitrary Server version or a 404 into a permission grant.
    if connection["edition"] not in {"enterprise_cloud", "dedicated"}:
        return {**result, "status": "NOT_REPORTED", "detail": "GITHUB_ENTERPRISE_EXPORT_EDITION_UNSUPPORTED"}
    key = ("github_export_access", api_base(connection["target"].get("host")), enterprise)
    if key in context.memo:
        return dict(context.memo[key])
    client = context.http_client()
    broker = None
    try:
        tx = Transport(client, origin=web_base(connection["target"].get("host")),
            options=MetadataOptions(), enterprise=enterprise, max_requests=10)
        broker = TokenBroker(tx, app_id=envelope.get("GITHUB_APP_ID"),
            private_key=envelope.get("GITHUB_APP_PRIVATE_KEY_BASE64"),
            client_factory=lambda: client, enterprise=enterprise)
        broker.app()
        installation = broker.installation_for("enterprise", enterprise)
        granted = installation["permissions"].get("enterprise_credentials") in {"read", "write", "admin"}
        result.update(status="GRANTED" if granted else "MISSING",
            detail="ENTERPRISE_INSTALLATION_PERMISSION_CONFIRMED" if granted else "GITHUB_ENTERPRISE_CREDENTIALS_READ_REQUIRED")
    except SourceError as exc:
        result.update(status="MISSING" if exc.status in {401, 403, 404}
            or "installation" in exc.code else "ERROR", detail=exc.code.upper())
    except (ValueError, Budget):
        result.update(status="NOT_REPORTED", detail="GITHUB_ENTERPRISE_INSTALLATION_UNVERIFIED")
    finally:
        if broker is not None:
            broker.close()
        client.close()
    context.memo[key] = dict(result)
    return result


def audit_access(connection, secrets, context):
    enterprise = connection["target"]["enterprise"]
    token = (secrets.get("audit_token") or {}).get("token")
    if not token:
        return {"permission": "enterprise_audit_read", "status": "MISSING",
                "subject": enterprise, "detail": "GITHUB_ENTERPRISE_AUDIT_TOKEN_REQUIRED"}
    with context.http_client() as client:
        return item("enterprise_audit_read", probe(client, "GET",
            f"{api_base(connection['target'].get('host'))}/enterprises/{enterprise}/audit-log?per_page=1",
            headers={"Authorization": "Bearer " + token, "Accept": "application/vnd.github+json",
                     "X-GitHub-Api-Version": API_VERSION}), subject=enterprise)
