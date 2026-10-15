"""Generic HTTP credential verifier.

Each entry in ``HTTP_VERIFY_SPECS`` describes how to ask one provider whether a
credential is valid, using a safe read-only endpoint from that provider's public
API documentation (recorded in ``doc``). The verifier injects the credential per
the documented auth scheme, sends one request through an injectable client, and
maps the response to a verification state — never storing or echoing the secret.
"""

from __future__ import annotations

import base64
import datetime as _dt
import json
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from cremore_github_provider.github_hosts import api_base as _gh_api_base

from cremore.detection.safe_text import safe_fact_text
from cremore.detection.verify import (
    VerificationResult,
    VerificationState,
    VerifierConfig,
    register,
)
from cremore.http_client import bounded_request

_MAX_PROBES = 5


@dataclass(frozen=True)
class CapabilityProbe:
    """One read-only call made with a *verified* secret to see what it can reach.

    Only for credential types whose provider does not report permissions in the
    verification response (a GitHub fine-grained PAT, a Notion integration). The
    URL is a fixed, documented, read-only endpoint — never taken from content —
    and a 2xx counts as reachable. ``count_path`` optionally records a bounded
    count from the body (a list length or an integer).
    """

    name: str
    method: str
    url: str
    doc: str
    body: str = ""
    count_path: str = ""


@dataclass(frozen=True)
class HTTPVerifySpec:
    detector_id: str
    method: str
    url: str
    # auth scheme: how the secret is presented.
    #   bearer     -> Authorization: Bearer <secret>
    #   token      -> Authorization: token <secret>
    #   bot        -> Authorization: Bot <secret>
    #   header     -> <header_name>: <secret>
    #   basic_user -> Authorization: Basic base64(<secret>:)
    auth: str
    doc: str
    header_name: str = ""
    extra_headers: dict[str, str] = field(default_factory=dict)
    success_statuses: frozenset[int] = frozenset({200})
    # A forbidden request can reflect permissions or rate limits, not a bad key.
    reject_statuses: frozenset[int] = frozenset({401})
    restricted_statuses: frozenset[int] = frozenset()
    # For providers (e.g. Slack) that always answer 200 and put the verdict in
    # the body: the body must contain success_body to count as verified, and
    # reject_body marks a definite rejection.
    success_body: str = ""
    reject_body: str = ""
    # Header whose value carries granted scopes; copied into facts["scopes"].
    scope_header: str = ""
    # Non-secret identity facts read from the same success response body:
    # (fact name, dotted JSON path). Nothing extra is requested from the provider.
    body_facts: tuple[tuple[str, str], ...] = ()
    # Header carrying the credential's own expiry, as "YYYY-MM-DD HH:MM:SS UTC".
    expiry_header: str = ""
    # Read-only calls made with the secret to record what it can reach, only when
    # capability probing is enabled (off by default). Never a write.
    capabilities: tuple[CapabilityProbe, ...] = ()
    # When True, ``url`` and each capability ``url`` are PATHS appended to the
    # GitHub API base for the host the token was found on (github.com or a GHES
    # ``/api/v3``), and rejection can be retried across known hosts.
    host_scoped: bool = False


HTTP_VERIFY_SPECS: tuple[HTTPVerifySpec, ...] = (
    HTTPVerifySpec(
        "github-token-v1", "GET", "/user", "token",
        "https://docs.github.com/en/rest/users/users#get-the-authenticated-user",
        extra_headers={"Accept": "application/vnd.github+json"},
        scope_header="X-OAuth-Scopes",
        body_facts=(("owner_name", "login"), ("owner_id", "id"), ("owner_kind", "type")),
        expiry_header="GitHub-Authentication-Token-Expiration",
        host_scoped=True,
        capabilities=(
            CapabilityProbe("read_repositories", "GET",
                            "/user/repos?per_page=1&affiliation=owner,collaborator,organization_member",
                            "https://docs.github.com/en/rest/repos/repos#list-repositories-for-the-authenticated-user",
                            count_path="[]"),
            CapabilityProbe("read_organizations", "GET", "/user/orgs?per_page=1",
                            "https://docs.github.com/en/rest/orgs/orgs#list-organizations-for-the-authenticated-user", count_path="[]"),
            CapabilityProbe("read_gists", "GET", "/gists?per_page=1",
                            "https://docs.github.com/en/rest/gists/gists#list-gists-for-the-authenticated-user", count_path="[]"),
        ),
    ),
    HTTPVerifySpec(
        # Any scope may read its own token (GitLab allows all scopes here), unlike
        # /user, and the answer names the token itself, not only its owner.
        "gitlab-pat-v1", "GET", "https://gitlab.com/api/v4/personal_access_tokens/self", "header",
        "https://docs.gitlab.com/api/personal_access_tokens/",
        header_name="PRIVATE-TOKEN",
        body_facts=(("token_id", "id"), ("owner_id", "user_id"), ("name", "name"), ("scopes", "scopes"),
                    ("expires_at", "expires_at")),
    ),
    HTTPVerifySpec(
        "slack-token-v1", "POST", "https://slack.com/api/auth.test", "bearer",
        "https://api.slack.com/methods/auth.test",
        success_body='"ok":true', reject_body='"ok":false',
    ),
    HTTPVerifySpec(
        "stripe-secret-key-v1", "GET", "https://api.stripe.com/v1/account", "basic_user",
        "https://docs.stripe.com/api/accounts/retrieve",
    ),
    HTTPVerifySpec(
        "openai-api-key-v1", "GET", "https://api.openai.com/v1/models", "bearer",
        "https://platform.openai.com/docs/api-reference/models/list",
    ),
    HTTPVerifySpec(
        "anthropic-api-key-v1", "GET", "https://api.anthropic.com/v1/models", "header",
        "https://docs.anthropic.com/en/api/models-list",
        header_name="x-api-key", extra_headers={"anthropic-version": "2023-06-01"},
    ),
    HTTPVerifySpec(
        "sendgrid-api-key-v1", "GET", "https://api.sendgrid.com/v3/scopes", "bearer",
        "https://www.twilio.com/docs/sendgrid/api-reference/api-key-permissions/retrieve-a-list-of-scopes-for-which-this-user-has-access",
    ),
    HTTPVerifySpec(
        "npm-token-v1", "GET", "https://registry.npmjs.org/-/npm/v1/user", "bearer",
        "https://docs.npmjs.com/about-access-tokens",
    ),
    HTTPVerifySpec(
        "digitalocean-pat-v1", "GET", "https://api.digitalocean.com/v2/account", "bearer",
        "https://docs.digitalocean.com/reference/api/api-reference/#operation/account_get",
    ),
    HTTPVerifySpec(
        "notion-token-v1", "GET", "https://api.notion.com/v1/users/me", "bearer",
        "https://developers.notion.com/reference/get-self",
        extra_headers={"Notion-Version": "2022-06-28"},
        body_facts=(("owner_name", "name"), ("owner_id", "id"), ("owner_kind", "type"),
                    ("workspace", "bot.workspace_name"), ("context_owner_kind", "bot.owner.type")),
        capabilities=(
            CapabilityProbe("read_shared_content", "POST", "https://api.notion.com/v1/search",
                            "https://developers.notion.com/reference/post-search",
                            body='{"page_size":1}', count_path="results"),
        ),
    ),
    HTTPVerifySpec(
        "figma-token-v1", "GET", "https://api.figma.com/v1/me", "header",
        "https://www.figma.com/developers/api#get-me-endpoint",
        header_name="X-Figma-Token",
    ),
    HTTPVerifySpec(
        "huggingface-token-v1", "GET", "https://huggingface.co/api/whoami-v2", "bearer",
        "https://huggingface.co/docs/hub/api#get-apiwhoami-v2",
    ),
    HTTPVerifySpec(
        "doppler-token-v1", "GET", "https://api.doppler.com/v3/me", "bearer",
        "https://docs.doppler.com/reference/auth-me",
    ),
    HTTPVerifySpec(
        "postman-api-key-v1", "GET", "https://api.getpostman.com/me", "header",
        "https://www.postman.com/postman-public-workspace/documentation/i2uqzpp/postman-api",
        header_name="X-Api-Key",
    ),
    HTTPVerifySpec(
        "airtable-pat-v1", "GET", "https://api.airtable.com/v0/meta/whoami", "bearer",
        "https://airtable.com/developers/web/api/get-user-id-scopes",
    ),
    HTTPVerifySpec(
        "replicate-token-v1", "GET", "https://api.replicate.com/v1/account", "bearer",
        "https://replicate.com/docs/reference/http#account.get",
    ),
    HTTPVerifySpec(
        "groq-api-key-v1", "GET", "https://api.groq.com/openai/v1/models", "bearer",
        "https://console.groq.com/docs/api-reference#models-list",
    ),
    # --- second set -------------------------------------------------------
    HTTPVerifySpec(
        "square-access-token-v1", "GET", "https://connect.squareup.com/v2/merchants", "bearer",
        "https://developer.squareup.com/reference/square/merchants-api/list-merchants",
    ),
    HTTPVerifySpec(
        "sentry-token-v1", "GET", "https://sentry.io/api/0/organizations/", "bearer",
        "https://docs.sentry.io/api/organizations/list-your-organizations/",
    ),
    HTTPVerifySpec(
        "circleci-pat-v1", "GET", "https://circleci.com/api/v2/me", "header",
        "https://circleci.com/docs/api/v2/index.html#operation/getCurrentUser",
        header_name="Circle-Token",
    ),
    HTTPVerifySpec(
        "dropbox-access-token-v1", "POST", "https://api.dropboxapi.com/2/users/get_current_account", "bearer",
        "https://www.dropbox.com/developers/documentation/http/documentation#users-get_current_account",
    ),
    HTTPVerifySpec(
        "pulumi-access-token-v1", "GET", "https://api.pulumi.com/api/user", "token",
        "https://www.pulumi.com/docs/pulumi-cloud/cloud-rest-api/",
    ),
    HTTPVerifySpec(
        "render-api-key-v1", "GET", "https://api.render.com/v1/owners", "bearer",
        "https://api-docs.render.com/reference/get-owners",
    ),
    HTTPVerifySpec(
        "launchdarkly-api-token-v1", "GET", "https://app.launchdarkly.com/api/v2/members", "header",
        "https://apidocs.launchdarkly.com/tag/Account-members/#operation/getMembers",
        header_name="Authorization",
    ),
    HTTPVerifySpec(
        "asana-pat-v1", "GET", "https://app.asana.com/api/1.0/users/me", "bearer",
        "https://developers.asana.com/reference/getuser",
    ),
    HTTPVerifySpec(
        "discord-bot-token-v1", "GET", "https://discord.com/api/users/@me", "bot",
        "https://discord.com/developers/docs/resources/user#get-current-user",
    ),
    HTTPVerifySpec(
        "xai-api-key-v1", "GET", "https://api.x.ai/v1/models", "bearer",
        "https://docs.x.ai/docs/api-reference#list-models",
    ),
    HTTPVerifySpec(
        "openrouter-api-key-v1", "GET", "https://openrouter.ai/api/v1/auth/key", "bearer",
        "https://openrouter.ai/docs/api-reference/authentication",
    ),
    HTTPVerifySpec(
        "tailscale-key-v1", "GET", "https://api.tailscale.com/api/v2/tailnet/-/devices", "basic_user",
        "https://tailscale.com/api",
    ),
    HTTPVerifySpec(
        "brevo-api-key-v1", "GET", "https://api.brevo.com/v3/account", "header",
        "https://developers.brevo.com/reference/getaccount",
        header_name="api-key",
    ),
    HTTPVerifySpec(
        "frameio-token-v1", "GET", "https://api.frame.io/v2/me", "bearer",
        "https://developer.frame.io/api/reference/operation/getAuthenticatedUser/",
    ),
    HTTPVerifySpec(
        "easypost-api-key-v1", "GET", "https://api.easypost.com/v2/api_keys", "basic_user",
        "https://docs.easypost.com/docs/authentication",
    ),
    HTTPVerifySpec(
        "heroku-api-key-v1", "GET", "https://api.heroku.com/account", "bearer",
        "https://devcenter.heroku.com/articles/platform-api-reference#account-info",
        extra_headers={"Accept": "application/vnd.heroku+json; version=3"},
    ),
    HTTPVerifySpec(
        "neon-api-key-v1", "GET", "https://console.neon.tech/api/v2/users/me", "bearer",
        "https://api-docs.neon.tech/reference/getcurrentuserinfo",
    ),
    HTTPVerifySpec(
        "contentful-pat-v1", "GET", "https://api.contentful.com/spaces", "bearer",
        "https://www.contentful.com/developers/docs/references/content-management-api/#/reference/spaces",
    ),
    # --- third set --------------------------------------------------------
    HTTPVerifySpec(
        "hubspot-token-v1", "GET", "https://api.hubapi.com/account-info/v3/details", "bearer",
        "https://developers.hubspot.com/docs/guides/apps/private-apps/overview",
    ),
    HTTPVerifySpec(
        "netlify-token-v1", "GET", "https://api.netlify.com/api/v1/user", "bearer",
        "https://docs.netlify.com/api/get-started/#authentication",
    ),
    HTTPVerifySpec(
        "linode-token-v1", "GET", "https://api.linode.com/v4/profile", "bearer",
        "https://techdocs.akamai.com/linode-api/reference/get-profile",
    ),
    HTTPVerifySpec(
        "vultr-api-key-v1", "GET", "https://api.vultr.com/v2/account", "bearer",
        "https://www.vultr.com/api/#tag/account",
    ),
    HTTPVerifySpec(
        "hetzner-api-token-v1", "GET", "https://api.hetzner.cloud/v1/servers", "bearer",
        "https://docs.hetzner.cloud/#servers-get-all-servers",
    ),
    HTTPVerifySpec(
        "cloudflare-api-token-v1", "GET", "https://api.cloudflare.com/client/v4/user/tokens/verify", "bearer",
        "https://developers.cloudflare.com/api/operations/user-api-tokens-verify-token",
    ),
    HTTPVerifySpec(
        "fastly-api-token-v1", "GET", "https://api.fastly.com/current_user", "header",
        "https://www.fastly.com/documentation/reference/api/auth/",
        header_name="Fastly-Key",
    ),
    HTTPVerifySpec(
        "pinecone-api-key-v1", "GET", "https://api.pinecone.io/indexes", "header",
        "https://docs.pinecone.io/reference/api/authentication",
        header_name="Api-Key",
    ),
    HTTPVerifySpec(
        "mistral-api-key-v1", "GET", "https://api.mistral.ai/v1/models", "bearer",
        "https://docs.mistral.ai/api/",
    ),
    HTTPVerifySpec(
        "elevenlabs-api-key-v1", "GET", "https://api.elevenlabs.io/v1/user", "header",
        "https://elevenlabs.io/docs/api-reference/authentication",
        header_name="xi-api-key",
    ),
    HTTPVerifySpec(
        "assemblyai-api-key-v1", "GET", "https://api.assemblyai.com/v2/transcript", "header",
        "https://www.assemblyai.com/docs/api-reference/overview",
        header_name="Authorization",
    ),
    HTTPVerifySpec(
        "togetherai-api-key-v1", "GET", "https://api.together.xyz/v1/models", "bearer",
        "https://docs.together.ai/reference/models-1",
    ),
    HTTPVerifySpec(
        "postmark-server-token-v1", "GET", "https://api.postmarkapp.com/server", "header",
        "https://postmarkapp.com/developer/api/overview#authentication",
        header_name="X-Postmark-Server-Token",
    ),
    HTTPVerifySpec(
        "sparkpost-api-key-v1", "GET", "https://api.sparkpost.com/api/v1/account", "header",
        "https://developers.sparkpost.com/api/#header-authentication",
        header_name="Authorization",
    ),
    HTTPVerifySpec(
        "snyk-api-token-v1", "GET", "https://api.snyk.io/v1/user/me", "token",
        "https://docs.snyk.io/snyk-api/authentication-for-api",
    ),
    HTTPVerifySpec(
        "cohere-api-key-v1", "POST", "https://api.cohere.com/v1/check-api-key", "bearer",
        "https://docs.cohere.com/reference/checkapikey",
    ),
    # --- fourth set -------------------------------------------------------
    HTTPVerifySpec(
        "coda-api-token-v1", "GET", "https://coda.io/apis/v1/whoami", "bearer",
        "https://coda.io/developers/apis/v1#operation/whoami",
    ),
    HTTPVerifySpec(
        "webex-token-v1", "GET", "https://webexapis.com/v1/people/me", "bearer",
        "https://developer.webex.com/docs/api/v1/people/get-my-own-details",
    ),
    HTTPVerifySpec(
        "box-token-v1", "GET", "https://api.box.com/2.0/users/me", "bearer",
        "https://developer.box.com/reference/get-users-me/",
    ),
    HTTPVerifySpec(
        "clickup-token-v1", "GET", "https://api.clickup.com/api/v2/user", "header",
        "https://clickup.com/api/clickupreference/operation/GetAuthorizedUser/",
        header_name="Authorization",
    ),
    HTTPVerifySpec(
        "shortcut-token-v1", "GET", "https://api.app.shortcut.com/api/v3/member", "header",
        "https://developer.shortcut.com/api/rest/v3#Get-Current-Member-Info",
        header_name="Shortcut-Token",
    ),
    HTTPVerifySpec(
        "typeform-pat-v1", "GET", "https://api.typeform.com/me", "bearer",
        "https://www.typeform.com/developers/create/reference/retrieve-account-info/",
    ),
    HTTPVerifySpec(
        "intercom-access-token-v1", "GET", "https://api.intercom.io/me", "bearer",
        "https://developers.intercom.com/docs/references/rest-api/api.intercom.io/admins/identifyadmin",
        extra_headers={"Accept": "application/json"},
    ),
    HTTPVerifySpec(
        "bitbucket-access-token-v1", "GET", "https://api.bitbucket.org/2.0/user", "bearer",
        "https://developer.atlassian.com/cloud/bitbucket/rest/api-group-users/#api-user-get",
    ),
    HTTPVerifySpec(
        "deepseek-api-key-v1", "GET", "https://api.deepseek.com/user/balance", "bearer",
        "https://api-docs.deepseek.com/api/get-user-balance",
    ),
    HTTPVerifySpec(
        "vercel-token-v1", "GET", "https://api.vercel.com/v2/user", "bearer",
        "https://vercel.com/docs/rest-api/endpoints/user#get-the-user",
    ),
    HTTPVerifySpec(
        "sentry-org-token-v1", "GET", "https://sentry.io/api/0/organizations/", "bearer",
        "https://docs.sentry.io/api/organizations/list-your-organizations/",
    ),
    HTTPVerifySpec(
        "supabase-token-v1", "GET", "https://api.supabase.com/v1/projects", "bearer",
        "https://supabase.com/docs/reference/api/introduction",
    ),
)


class HTTPVerifier:
    def __init__(self, spec: HTTPVerifySpec) -> None:
        self.spec = spec

    def _auth_headers(self, secret: str) -> dict[str, str]:
        s = self.spec
        headers = dict(s.extra_headers)
        if s.auth == "bearer":
            headers["Authorization"] = f"Bearer {secret}"
        elif s.auth == "token":
            headers["Authorization"] = f"token {secret}"
        elif s.auth == "bot":
            headers["Authorization"] = f"Bot {secret}"
        elif s.auth == "header":
            headers[s.header_name] = secret
        elif s.auth == "basic_user":
            encoded = base64.b64encode(f"{secret}:".encode()).decode()
            headers["Authorization"] = f"Basic {encoded}"
        else:  # pragma: no cover - guarded at registration
            raise ValueError(f"unknown auth scheme {s.auth!r}")
        return headers

    def _bases(self, config: VerifierConfig, context: dict | None) -> list[str]:
        """API bases to try, in order, for a host-scoped credential.

        The host the token was found on comes first; with cross-host enabled the
        other registered hosts follow, so a token that is not this server's is
        still confirmed instead of falsely called inactive. Non-host-scoped specs
        return one empty base (the spec URLs are already absolute).
        """
        if not self.spec.host_scoped:
            return [""]
        ctx = context or {}
        primary = _gh_api_base(ctx.get("github_host"))
        bases = [primary]
        if config.cross_host:
            # Every other registered host, plus github.com — a discovered token
            # could belong to the public GitHub even when found on a GHES server.
            for host in (*config.known_github_hosts, ""):
                base = _gh_api_base(host)
                if base not in bases:
                    bases.append(base)
        return bases

    def verify(
        self,
        *,
        secret: str,
        identifier: str,
        config: VerifierConfig,
        client: object | None = None,
        context: dict | None = None,
    ) -> VerificationResult:
        if not config.enabled:
            return VerificationResult(VerificationState.NOT_ATTEMPTED)

        ctx = context or {}
        if (self.spec.host_scoped and not ctx.get("github_host") and ctx.get("source_type") != "github"
                and any(h not in ("", "github.com", "api.github.com") for h in config.known_github_hosts)
                and not config.cross_host):
            return VerificationResult(VerificationState.UNSUPPORTED, error_code="GITHUB_ISSUER_HOST_UNCONFIRMED")

        # A GitLab token goes to GitLab.com, or to the one registered self-managed
        # instance whose source it was found in. A self-managed source never
        # authorizes sending its tokens to GitLab.com, and a token found outside
        # GitLab while a self-managed instance is registered goes to GitLab.com
        # only when the admin allowed cross-host verification.
        gitlab_issuer_unconfirmed = False
        self_managed = ""
        if self.spec.detector_id == "gitlab-pat-v1":
            ctx = context or {}
            if ctx.get("source_type") == "gitlab" and ctx.get("source_instance") != "https://gitlab.com":
                # The source's base URL comes from the admin-registered connection,
                # never from scanned content; its host must also be a registered one.
                self_managed = _registered_gitlab_base(ctx.get("source_instance"), config.known_gitlab_hosts)
                if not self_managed:
                    return VerificationResult(VerificationState.UNSUPPORTED, error_code="GITLAB_ISSUER_HOST_UNCONFIRMED")
            else:
                gitlab_issuer_unconfirmed = ctx.get("source_type") != "gitlab" and bool(config.known_gitlab_hosts)
                if gitlab_issuer_unconfirmed and not config.cross_host:
                    return VerificationResult(VerificationState.UNSUPPORTED, error_code="GITLAB_ISSUER_HOST_UNCONFIRMED")

        try:
            # A self-managed instance serves the same API path under its own base URL.
            bases = [self_managed] if self_managed else self._bases(config, context)
            path = urlsplit(self.spec.url).path if self_managed else self.spec.url
            known = 1 if not self.spec.host_scoped else len({_gh_api_base(h) for h in (
                "", (context or {}).get("github_host", ""), *config.known_github_hosts)})
        except (TypeError, ValueError):
            return VerificationResult(VerificationState.INDETERMINATE, error_code="PROVIDER_CONFIGURATION_INVALID")
        headers = self._auth_headers(secret)
        owns_client = client is None
        if client is None:
            import httpx

            client = httpx.Client(timeout=config.timeout, follow_redirects=False)
        # How many GitHub hosts this token could belong to: github.com is always
        # possible, so if any GHES host is also registered, a rejection by one
        # host alone is not proof the token is dead on the others.
        try:
            rejected: VerificationResult | None = None
            inconclusive: VerificationResult | None = None
            for base in bases:
                try:
                    resp = bounded_request(client, self.spec.method, base + path, headers=headers)
                except Exception:  # noqa: BLE001 -- Untrusted provider errors must remain inconclusive without exposing response secrets.
                    return VerificationResult(VerificationState.INDETERMINATE, error_code="PROVIDER_UNREACHABLE")
                result = self._interpret(resp)
                result.facts = {name: value for name, value in result.facts.items()
                                if safe_fact_text(value, secrets=(secret,)) is not None}
                if result.state == VerificationState.VERIFIED:
                    if self.spec.host_scoped:
                        result.facts["host"] = _host_label(base)
                    elif self_managed:
                        # Token ids are per instance; the host ties this one to that instance's inventory.
                        result.facts["host"] = _gitlab_host(self_managed)
                    if config.probe_capabilities and self.spec.capabilities:
                        caps = self._probe_capabilities(secret, client, base)
                        if caps:
                            result.facts["capabilities"] = json.dumps(caps, separators=(",", ":"))
                    return result
                if result.state == VerificationState.REJECTED:
                    rejected = result
                elif inconclusive is None:
                    inconclusive = result
            if inconclusive is not None:
                return inconclusive
            if rejected is None:
                return VerificationResult(VerificationState.INDETERMINATE, error_code="PROVIDER_UNREACHABLE")
            if gitlab_issuer_unconfirmed:
                # GitLab.com saying no says nothing about a self-managed token.
                return VerificationResult(VerificationState.INDETERMINATE,
                                          error_code="REJECTED_ON_GITLAB_COM_SELF_MANAGED_UNCHECKED")
            if self_managed:
                # Neither does one instance saying no: the token may be GitLab.com's or another
                # instance's, and it is never sent there, so it is not called inactive.
                return VerificationResult(VerificationState.INDETERMINATE,
                                          error_code="REJECTED_ON_SELF_MANAGED_GITLAB_OTHER_HOSTS_UNCHECKED",
                                          facts={"host": _gitlab_host(self_managed)})
            # A lone host rejected but other GitHub hosts were not tried: do not
            # claim the token is inactive — say only that this host rejected it.
            if (self.spec.host_scoped and rejected.state == VerificationState.REJECTED
                    and len(bases) == 1 and known > 1):
                return VerificationResult(VerificationState.INDETERMINATE,
                                          error_code="REJECTED_ON_" + _host_label(bases[0]) + "_OTHER_HOSTS_UNCHECKED",
                                          facts={"host": _host_label(bases[0])})
            if self.spec.host_scoped and rejected.state == VerificationState.REJECTED:
                rejected.facts.setdefault("host", _host_label(bases[-1]))
            return rejected
        finally:
            if owns_client:
                try:
                    client.close()
                except Exception:  # noqa: BLE001, S110 -- Best-effort close must not replace the result or log credential-bearing errors.
                    pass

    def _interpret(self, resp) -> VerificationResult:
        s = self.spec
        status = resp.status_code
        body = _safe_text(resp)

        if s.detector_id == "slack-token-v1":
            try:
                payload = json.loads(body) if len(body) <= 1 << 20 else None
            except ValueError:
                payload = None
            if status == 200 and isinstance(payload, dict):
                if payload.get("ok") is True:
                    return self._verified(resp)
                if payload.get("ok") is False and payload.get("error") in (
                    "invalid_auth", "token_revoked", "account_inactive", "token_expired"
                ):
                    return VerificationResult(VerificationState.REJECTED, error_code="PROVIDER_REJECTED")
            return VerificationResult(VerificationState.INDETERMINATE, error_code=f"HTTP_{status}")

        # Body-verdict providers (always 200).
        if s.success_body or s.reject_body:
            if s.reject_body and s.reject_body in body:
                return VerificationResult(VerificationState.REJECTED, error_code="PROVIDER_REJECTED")
            if s.success_body and s.success_body in body:
                return self._verified(resp)
            return VerificationResult(VerificationState.INDETERMINATE, error_code=f"HTTP_{status}")

        if status in s.restricted_statuses:
            return VerificationResult(VerificationState.RESTRICTED, error_code=f"HTTP_{status}")
        if status in s.success_statuses:
            return self._verified(resp)
        if status in s.reject_statuses:
            return VerificationResult(VerificationState.REJECTED, error_code=f"HTTP_{status}")
        return VerificationResult(VerificationState.INDETERMINATE, error_code=f"HTTP_{status}")

    def _verified(self, resp) -> VerificationResult:
        facts: dict[str, str] = {}
        if self.spec.scope_header:
            scopes = _header(resp, self.spec.scope_header)
            if isinstance(scopes, str) and scopes and len(scopes) <= 256 and safe_fact_text(scopes) is not None:
                facts["scopes"] = scopes
        if self.spec.body_facts:
            facts.update(_body_facts(_safe_text(resp), self.spec.body_facts))
        if self.spec.expiry_header and (expires := _expiry(_header(resp, self.spec.expiry_header))):
            facts["expires_at"] = expires
        return VerificationResult(VerificationState.VERIFIED, facts=facts)


    def _probe_capabilities(self, secret: str, client, base: str = "") -> list[dict]:
        """Bounded read-only calls with the secret; each records only ALLOWED/DENIED and a count."""
        auth = self._auth_headers(secret)
        out: list[dict] = []
        for cap in self.spec.capabilities[:_MAX_PROBES]:
            headers = dict(auth)
            kwargs: dict = {}
            if cap.body:
                headers["Content-Type"] = "application/json"
                kwargs["content"] = cap.body.encode()
            try:
                resp = bounded_request(client, cap.method, base + cap.url, headers=headers, **kwargs)
            except Exception:  # noqa: BLE001 -- Untrusted provider errors must remain inconclusive without exposing response secrets.
                out.append({"name": cap.name, "status": "UNREACHABLE"})
                continue
            code = resp.status_code
            status = "ALLOWED" if 200 <= code < 300 else "DENIED" if code in (401, 403, 404) else f"HTTP_{code}"
            row = {"name": cap.name, "status": status}
            if status == "ALLOWED" and cap.count_path:
                count = _count_at(_safe_text(resp), cap.count_path)
                if count is not None:
                    row["count"] = count
            out.append(row)
        return out


def _registered_gitlab_base(source_instance, known_hosts) -> str:
    """The self-managed GitLab base URL to verify a token against, or "" to send nothing.

    ``source_instance`` is the base URL of the admin-registered GitLab connection the
    token was found in; ``known_hosts`` are the hosts of every registered GitLab
    connection. The URL is re-checked with the registration rule, and an unregistered
    host or GitLab.com (which a self-managed source never authorizes) yields "".
    """
    from cremore.sources.validation import https_base

    try:
        base = https_base(source_instance)
    except ValueError:
        return ""
    host = (urlsplit(base).hostname or "").lower()
    return base if host and host != "gitlab.com" and host in known_hosts else ""


def _gitlab_host(base: str) -> str:
    """A safe host label for a self-managed GitLab verification fact."""
    host = (urlsplit(base).hostname or "").lower()
    return host if host and set(host) <= set("abcdefghijklmnopqrstuvwxyz0123456789.-") else "unknown_host"


def _host_label(api_base: str) -> str:
    """A short, safe host label for a fact ("github.com" or a GHES hostname)."""
    from cremore_github_provider.github_hosts import PUBLIC_API
    if not api_base or api_base == PUBLIC_API:
        return "github.com"
    host = api_base.removeprefix("https://").split("/", 1)[0]
    return host if host and set(host) <= set("abcdefghijklmnopqrstuvwxyz0123456789.-") else "unknown_host"


def _count_at(text: str, path: str):
    """A bounded count at ``path``: list length, or int, capped at 1000."""
    if not text or len(text) > 1 << 20:
        return None
    try:
        data = json.loads(text)
    except ValueError:
        return None
    if path != "[]":
        for part in path.split("."):
            data = data.get(part) if isinstance(data, dict) else None
    if isinstance(data, list):
        return min(len(data), 1000)
    if isinstance(data, int) and not isinstance(data, bool) and data >= 0:
        return min(data, 1000)
    return None


def _safe_text(resp) -> str:
    try:
        return resp.text or ""
    except Exception:  # noqa: BLE001 -- Unreadable response metadata supplies no evidence; never log its sensitive contents.
        return ""


def _body_facts(text: str, paths: tuple[tuple[str, str], ...]) -> dict[str, str]:
    """Plain scalar values at fixed paths, bounded; anything else is ignored."""
    if not text or len(text) > 1 << 20:
        return {}
    try:
        data = json.loads(text)
    except ValueError:
        return {}
    out = {}
    for name, path in paths:
        value = data
        for part in path.split("."):
            value = value.get(part) if isinstance(value, dict) else None
        if isinstance(value, list) and len(value) <= 32 and all(isinstance(item, str) for item in value):
            value = ", ".join(value)  # e.g. GitLab token scopes
        if isinstance(value, bool) or not isinstance(value, (str, int)):
            continue
        value = str(value)
        if value and len(value) <= 256 and safe_fact_text(value) is not None:
            out[name] = value
    return out


def _expiry(raw: str) -> str:
    try:
        return _dt.datetime.strptime(raw.strip(), "%Y-%m-%d %H:%M:%S UTC").replace(tzinfo=_dt.UTC).isoformat()
    except ValueError:
        return ""


def _header(resp, name: str) -> str:
    try:
        return resp.headers.get(name, "") or ""
    except Exception:  # noqa: BLE001 -- Unreadable response metadata supplies no evidence; never log its sensitive contents.
        return ""


def register_all() -> None:
    for spec in HTTP_VERIFY_SPECS:
        register(spec.detector_id, HTTPVerifier(spec))
