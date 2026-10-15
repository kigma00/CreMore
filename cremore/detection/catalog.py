"""Detector catalog.

Every detector here is written from the named provider's public documentation
(recorded in ``source_url``). Patterns use
only RE2-safe constructs (no backreferences or lookaround) so they run under
both regex backends and carry the same linear-time guarantee the engine relies
on.

This is the first batch. It covers the credential formats that appear most often
in real leaks and that providers document with a stable, recognisable shape. The
long tail is added the same way: one documented format at a time.
"""

from __future__ import annotations

import re

from cremore.detection.models import CatalogEntry, Definition, PatternDef, PatternRole
from cremore.detection.validators import basic_auth_b64, min_entropy

# A byte class matching a character that is NOT part of a token, used to anchor a
# prefixed token so a longer surrounding identifier does not swallow it.
_BOUNDARY = r"[^A-Za-z0-9_-]"
# The current Entra client secret shape, owned by azure-entra-client-secret-v1.
_ENTRA_SHAPED = re.compile(rb"[A-Za-z0-9_~.-]{3}[0-9]Q~[A-Za-z0-9_~.-]{31,34}")


def prefix_detector(
    det_id: str,
    name: str,
    provider: str,
    credential_type: str,
    keywords: tuple[str, ...],
    token_pattern: str,
    source_url: str,
    description: str = "",
    confidence: str = "high",
    validate: object | None = None,
) -> Definition:
    """A single-secret detector for a provider-documented prefixed token.

    The token is anchored between non-token boundaries so it is captured whole
    and not as a fragment of a longer string.
    """

    expr = rf"(?:^|{_BOUNDARY})(?P<secret>{token_pattern})(?:$|{_BOUNDARY})"
    return Definition(
        catalog=CatalogEntry(
            id=det_id,
            name=name,
            provider=provider,
            credential_type=credential_type,
            description=description or "A provider-documented credential with a bounded token format.",
            keywords=keywords,
            match_strategy="documented prefix and bounded format",
            source_url=source_url,
            confidence=confidence,
        ),
        validate=validate,
        detector_name="CreMoreNative" + _compact(name),
        patterns=(
            PatternDef(
                role=PatternRole.SECRET,
                expr=expr,
                secret_group="secret",
                fingerprint_groups=("secret",),
            ),
        ),
    )


def regex_detector(
    det_id: str,
    name: str,
    provider: str,
    credential_type: str,
    keywords: tuple[str, ...],
    expr: str,
    source_url: str,
    description: str = "",
    match_strategy: str = "documented format",
    secret_group: str = "secret",
    span: int = 0,
    confidence: str = "high",
    validate: object | None = None,
) -> Definition:
    """A single-secret detector whose expression names its secret group."""

    return Definition(
        catalog=CatalogEntry(
            id=det_id,
            name=name,
            provider=provider,
            credential_type=credential_type,
            description=description or "A provider-documented credential format.",
            keywords=keywords,
            match_strategy=match_strategy,
            source_url=source_url,
            confidence=confidence,
        ),
        detector_name="CreMoreNative" + _compact(name),
        span=span,
        validate=validate,
        patterns=(
            PatternDef(
                role=PatternRole.SECRET,
                expr=expr,
                secret_group=secret_group,
                fingerprint_groups=(secret_group,),
            ),
        ),
    )


# Leading segments that are unambiguously a code reference rather than a literal,
# in any file format. Kept deliberately short: an unquoted dotted value such as
# ``alpha.beta.gamma`` in a .env file is a perfectly ordinary password, so a bare
# dotted value is NOT treated as code. When in doubt the value is kept.
_CODE_ROOTS = ("process.env", "os.environ", "system.getenv", "self.", "this.",
               "props.", "proptypes.")


def _generic_value_is_literal(data: bytes) -> bool:
    """Reject only values that cannot be the secret itself.

    Two shapes are excluded whether or not they are quoted, because both resolve
    elsewhere at runtime: a substitution (``${DB_PASSWORD}``, ``{{ vault_pw }}``,
    ``%(password)s``) and a reference rooted in a known code object
    (``process.env.DB_PASS``, ``self.password_value``, ``PropTypes.string``).

    Everything else is kept, including weak, repetitive or code-looking literals —
    ``"aaaabbbb"`` and ``"getPassword()"`` are still literals, and a bare
    ``alpha.beta.gamma`` in a .env file is still a password.
    """

    text = data.decode("utf-8", "replace").strip()
    if text.startswith("$") or "${" in text or "{{" in text or "%(" in text:
        return False
    lowered = text.lower()
    return not any(lowered.startswith(root) for root in _CODE_ROOTS)


# Two ways a label followed by ":" is not an assignment at all. The checks run on
# the same-line text before the secret, which ends with the label, the separator
# and (for a quoted value) the quote the pattern took as the opening one.
# 1. A complete Secrets Manager ARN: `...:123456789012:secret:name` names a
#    secret; the text after `secret:` is its name, not its value.
_SECRETS_MANAGER_ARN = re.compile(rb"arn:aws[a-z-]*:secretsmanager:[a-z0-9-]+:\d{12}:secret:\Z")
# 2. A standalone string literal holding only the label between colons, as in
#    `arn.split(":secret:")[1]`. The quote after it closes that literal, so what
#    follows is code. `{"service:secret": "v"}` does not match: its label is not
#    the whole literal, and it stays an assignment.
_COLON_LABEL_LITERAL = re.compile(rb"(?:\A|[^\w\\])([\"']):[A-Za-z_-]+:\1\Z")


def _generic_assignment_context(before: bytes, secret: bytes) -> bool:
    return not (_SECRETS_MANAGER_ARN.search(before) or _COLON_LABEL_LITERAL.search(before))


def generic_assignment_detector(
    det_id: str,
    name: str,
    credential_type: str,
    keywords: tuple[str, ...],
    label_regex: str,
    quoted_value: str,
    unquoted_value: str,
    source_url: str,
    description: str = "",
) -> Definition:
    """A generic hardcoded-credential detector that reads its assignment context.

    Unlike :func:`labeled_secret_detector` (shared with provider detectors, and
    left untouched), this distinguishes a quoted string literal from a bare
    expression, because ``password = getPassword()`` and
    ``password = "getPassword()"`` do not mean the same thing. A quoted value is
    a literal and is kept whatever it looks like; an unquoted value is only kept
    when it is not obviously a call, an interpolation or a known code reference.

    No entropy floor is applied: a weak or repetitive password is still a
    password. ``FPPolicy`` annotates low-entropy and placeholder values as
    review signals instead, so they are retained rather than dropped.
    """

    # The engine compiles with RE2, which has no conditionals, backreferences or
    # lookaround, so quoted and bare assignments are separate SECRET patterns.
    # The engine ORs them (each is tried independently) and applies one validator.
    # Spacing around the assignment stays on one line: an empty `PASSWORD=` must
    # never borrow the next line (`FINGERPRINT_KEY=`) as its value.
    assign = rf"(?i:{label_regex})[\"']?[ \t]*[:=][ \t]*"
    patterns = tuple(
        PatternDef(role=PatternRole.SECRET, expr=expr, secret_group="secret",
                   fingerprint_groups=("secret",))
        for expr in (
            rf"{assign}\"(?P<secret>{quoted_value})\"",
            rf"{assign}'(?P<secret>{quoted_value})'",
            # A bare value must end at a real delimiter or end of input. "(" is
            # excluded on purpose: `password = getPassword()` would otherwise
            # match the bare name in front of the call.
            rf"{assign}(?P<secret>{unquoted_value})(?:[\s,;)}}\]]|$)",
        )
    )
    return Definition(
        catalog=CatalogEntry(
            id=det_id, name=name, provider="generic", credential_type=credential_type,
            description=description, keywords=keywords,
            match_strategy="assignment context (quoted literal or bare value)",
            source_url=source_url, confidence="low",
        ),
        detector_name="CreMoreNative" + _compact(name),
        span=256,
        validate=_generic_value_is_literal,
        context_validate=_generic_assignment_context,
        patterns=patterns,
    )


def labeled_secret_detector(
    det_id: str,
    name: str,
    provider: str,
    credential_type: str,
    keywords: tuple[str, ...],
    label_regex: str,
    value_pattern: str,
    source_url: str,
    description: str = "",
    span: int = 0,
    confidence: str = "medium",
    validate: object | None = None,
) -> Definition:
    """A detector for a provider whose value has no distinctive shape of its own.

    Many providers document their secret only as "a 32-hex string" or similar,
    which is too generic to match on its own. This requires the documented config
    label (``label_regex``, e.g. ``datadog[_-]?api[_-]?key``) to sit just before
    the value, so the match is anchored by context rather than by the value alone
    — the same label-proximity approach the keyword router already relies on.
    """

    expr = rf"(?i:{label_regex})[\"'\s:=]{{1,8}}(?P<secret>{value_pattern})"
    return regex_detector(
        det_id, name, provider, credential_type, keywords, expr, source_url,
        description=description or "A provider credential anchored to its documented config label.",
        match_strategy="labelled value (config key adjacent)",
        span=span or 256,
        # A value recognised only by an adjacent label is inherently less certain
        # than a self-identifying format, so it carries medium (or lower) confidence.
        confidence=confidence,
        validate=validate,
    )


# A conservative token-shaped value for label-gated providers whose exact key
# length is not pinned down: 20-100 token characters. The adjacent config label
# (not this value) is what makes the match specific, so this stays permissive to
# avoid misses while the label keeps false positives down.
_GENERIC_TOKEN = r"[A-Za-z0-9_\-.+/=]{20,100}"


def _keywords_from_label(label_regex: str) -> tuple[str, ...]:
    """Derive routable keyword substrings from a label regex's literal run.

    Takes the leading literal word (before any regex metacharacter) so the
    keyword router has a concrete string to match, e.g. ``raygun`` from
    ``raygun[_-]?(?:api[_-]?)?key``.
    """

    lead = re.match(r"[a-z0-9]+", label_regex)
    return (lead.group(0),) if lead else ()


def _labelled_batch(rows: list[tuple[str, str, str, str, str, str]]) -> list[Definition]:
    """Build a batch of low-confidence, label-gated provider detectors.

    Each row is (det_id, name, provider, credential_type, label_regex,
    source_url); the value is the conservative generic token and the keyword is
    derived from the label's leading literal.
    """

    out: list[Definition] = []
    for det_id, name, provider, credential_type, label_regex, source_url in rows:
        out.append(labeled_secret_detector(
            det_id, name, provider, credential_type,
            _keywords_from_label(label_regex), label_regex, _GENERIC_TOKEN, source_url,
            confidence="low",
        ))
    return out


def _compact(value: str) -> str:
    return "".join(ch for ch in value if ch.isalnum())


def builtin_definitions() -> list[Definition]:
    """The built-in detector set. Extend by appending documented formats."""

    d: list[Definition] = []
    from cremore_aws_provider.detection.session_material import TOKEN_PATTERN

    # ------------------------------------------------------------------ Cloud
    # Pair only adjacent literal fields/values, never arbitrary intervening text.
    # Parts outside this syntax/range remain independent observations below.
    aws_id = r"(?P<id>(?:AKIA|ASIA)[A-Z0-9]{16})"
    aws_secret = r"(?P<secret>[A-Za-z0-9/+=]{40})"
    aws_join = r'''["']?(?:[ \t]+|[ \t]*,[ \t]*(?:\r?\n[ \t]*)?|[ \t]*\r?\n[ \t]*)["']?'''
    secret_label = r"(?:aws[_-]?)?secret[_-]?access[_-]?key"
    id_label = r"(?:aws[_-]?)?access[_-]?key[_-]?id"
    secret_assignment = rf'''(?i:{secret_label})["']?[ \t]*[:=][ \t]*["']?'''
    id_assignment = rf'''(?i:{id_label})["']?[ \t]*[:=][ \t]*["']?'''
    d.append(
        Definition(
            catalog=CatalogEntry(
                id="aws-access-key-pair-v1",
                name="AWS access key pair",
                provider="aws",
                credential_type="AWS_ACCESS_KEY",
                description="Adjacent AWS key fields or literals; unpaired parts are reported separately.",
                keywords=("akia", "asia", "aws_secret_access_key", "aws_access_key_id"),
                match_strategy="adjacent multipart assignment with exact token boundaries",
                source_url="https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html#identifiers-unique-ids",
            ),
            detector_name="CreMoreNativeAWSAccessKey",
            span=1024,
            # The 40-char secret is base64-shaped and thus easy to match by
            # accident; require real randomness so low-entropy filler is rejected.
            validate=min_entropy(3.0),
            patterns=(
                PatternDef(
                    role=PatternRole.SECRET,
                    expr=rf"{aws_id}(?:{aws_join})(?:{secret_assignment})?{aws_secret}",
                    secret_group="secret",
                    identifier_group="id",
                    fingerprint_groups=("id", "secret"),
                ),
                PatternDef(
                    role=PatternRole.SECRET,
                    expr=rf"{aws_secret}(?:{aws_join})(?:{id_assignment})?{aws_id}",
                    secret_group="secret",
                    identifier_group="id",
                    fingerprint_groups=("id", "secret"),
                ),
            ),
        )
    )
    d.extend([
        Definition(
            catalog=CatalogEntry(
                id="aws-access-key-id-v1", name="AWS access key identifier only", provider="aws",
                credential_type="AWS_ACCESS_KEY_ID", keywords=("akia", "asia"),
                description="An identifier observation, not proof of secret exposure or usability.",
                match_strategy="exact identifier boundaries; paired occurrences excluded",
                source_url="https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html",
            ),
            detector_name="CreMoreNativeAWSAccessKeyID",
            patterns=(PatternDef(expr=aws_id, secret_group="id", identifier_group="id",
                                 fingerprint_groups=("id",)),),
        ),
        Definition(
            catalog=CatalogEntry(
                id="aws-secret-access-key-v1", name="AWS secret access key only", provider="aws",
                credential_type="AWS_SECRET_ACCESS_KEY", keywords=("secret",), confidence="medium",
                description="A labelled secret component without an established access-key pair.",
                match_strategy="AWS secret field with exact value boundaries; paired occurrences excluded",
                source_url="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html",
            ),
            detector_name="CreMoreNativeAWSSecretAccessKey",
            patterns=(PatternDef(expr=rf"(?:^|[^A-Za-z0-9_]){secret_assignment}{aws_secret}",
                                 secret_group="secret", fingerprint_groups=("secret",)),),
        ),
        Definition(
            catalog=CatalogEntry(
                id="aws-session-token-v1", name="AWS session token component", provider="aws",
                credential_type="AWS_SESSION_TOKEN", keywords=("session",), confidence="medium",
                description="A labelled STS token component; a token alone does not establish a usable session.",
                match_strategy="bounded labelled token; complete same-input session components linked separately",
                source_url="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_use-resources.html",
            ),
            detector_name="CreMoreNativeAWSSessionToken",
            patterns=(PatternDef(expr=rf'''(?:^|[^A-Za-z0-9_])(?i:(?:aws[_-]?)?session[_-]?token)["']?[ \t]*[:=][ \t]*["']?(?P<secret>{TOKEN_PATTERN})''',
                                 secret_group="secret", fingerprint_groups=("secret",)),),
        ),
    ])
    d += [
        prefix_detector(
            "gcp-api-key-v1", "Google API key", "gcp", "GCP_API_KEY",
            ("aiza",), r"AIza[0-9A-Za-z_\-]{35}",
            "https://cloud.google.com/docs/authentication/api-keys",
        ),
        regex_detector(
            "gcp-service-account-key-v1", "Google service account key", "gcp", "GCP_SERVICE_ACCOUNT",
            ("private_key", "service_account", "gserviceaccount"),
            # RE2 caps counted repetition at 1000; the scan window (span) bounds the block.
            r'(?P<secret>-----BEGIN PRIVATE KEY-----[\s\S]{100,}?-----END PRIVATE KEY-----)',
            "https://cloud.google.com/iam/docs/keys-create-delete",
            description="A Google service-account JSON key contains a PEM private key.",
            span=4096,
        ),
        prefix_detector(
            "digitalocean-pat-v1", "DigitalOcean personal access token", "digitalocean", "DIGITALOCEAN_TOKEN",
            ("dop_v1_", "doo_v1_", "dor_v1_"), r"do[opr]_v1_[a-f0-9]{64}",
            "https://docs.digitalocean.com/reference/api/create-personal-access-token/",
        ),
        prefix_detector(
            "cloudflare-origin-ca-key-v1", "Cloudflare Origin CA key", "cloudflare", "CLOUDFLARE_ORIGIN_CA_KEY",
            ("v1.0-",), r"v1\.0-[A-Fa-f0-9]{24}-[A-Za-z0-9+/=]{146,180}",
            "https://developers.cloudflare.com/ssl/origin-configuration/origin-ca/",
        ),
        prefix_detector(
            "flyio-token-v1", "Fly.io token", "flyio", "FLYIO_TOKEN",
            ("flyv1 ", "fm2_", "fo1_"), r"(?:FlyV1 fm2_[A-Za-z0-9+/=,]{80,}|f[mo][12]_[A-Za-z0-9+/=]{80,})",
            "https://fly.io/docs/security/tokens/",
        ),
        prefix_detector(
            "doppler-token-v1", "Doppler token", "doppler", "DOPPLER_TOKEN",
            ("dp.pt.", "dp.st.", "dp.sa.", "dp.scim."), r"dp\.(?:pt|st|sa|scim|audit)\.[A-Za-z0-9]{40,44}",
            "https://docs.doppler.com/docs/service-tokens",
        ),
        prefix_detector(
            "grafana-service-account-token-v1", "Grafana service account token", "grafana", "GRAFANA_TOKEN",
            ("glsa_", "glc_"), r"gl(?:sa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}|c_[A-Za-z0-9+/]{32,}={0,2})",
            "https://grafana.com/docs/grafana/latest/administration/service-accounts/",
        ),
        prefix_detector(
            "databricks-pat-v1", "Databricks personal access token", "databricks", "DATABRICKS_TOKEN",
            ("dapi",), r"dapi[a-f0-9]{32}(?:-\d)?",
            "https://docs.databricks.com/en/dev-tools/auth/pat.html",
        ),
        regex_detector(
            "terraform-cloud-token-v1", "Terraform Cloud token", "hashicorp", "TERRAFORM_CLOUD_TOKEN",
            ("atlasv1",), r"(?P<secret>[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9._-]{60,100})",
            "https://developer.hashicorp.com/terraform/cloud-docs/users-teams-organizations/api-tokens",
        ),
        prefix_detector(
            "vault-service-token-v1", "HashiCorp Vault service token", "hashicorp", "VAULT_TOKEN",
            ("hvs.", "hvb.", "hvr."), r"hv[sbr]\.[A-Za-z0-9]{24,100}",
            "https://developer.hashicorp.com/vault/docs/concepts/tokens",
        ),
        prefix_detector(
            "newrelic-user-key-v1", "New Relic user key", "newrelic", "NEWRELIC_KEY",
            ("nrak-",), r"NRAK-[A-Z0-9]{27}",
            "https://docs.newrelic.com/docs/apis/intro-apis/new-relic-api-keys/",
        ),

        # -------------------------------------------------------------- VCS
        prefix_detector(
            "github-token-v1", "GitHub token", "github", "GITHUB_TOKEN",
            ("ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"),
            r"(?:gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59})",
            "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/about-authentication-to-github#githubs-token-formats",
        ),
        prefix_detector(
            "gitlab-pat-v1", "GitLab personal access token", "gitlab", "GITLAB_PERSONAL_ACCESS_TOKEN",
            ("glpat-",), r"glpat-[A-Za-z0-9_-]{20}",
            "https://docs.gitlab.com/ee/security/token_overview.html",
        ),

        # ---------------------------------------------------------- Payment
        prefix_detector(
            "stripe-secret-key-v1", "Stripe secret key", "stripe", "STRIPE_SECRET_KEY",
            ("sk_live_", "rk_live_"), r"[sr]k_live_[A-Za-z0-9]{24,99}",
            "https://docs.stripe.com/keys",
        ),
        prefix_detector(
            "stripe-webhook-secret-v1", "Stripe webhook signing secret", "stripe", "STRIPE_WEBHOOK_SECRET",
            ("whsec_",), r"whsec_[A-Za-z0-9]{32,64}",
            "https://docs.stripe.com/webhooks/signature",
        ),
        prefix_detector(
            "square-access-token-v1", "Square access token", "square", "SQUARE_TOKEN",
            ("sq0atp-", "sq0csp-", "eaaa"), r"(?:sq0(?:atp|csp)-[A-Za-z0-9_-]{22,43}|EAAA[A-Za-z0-9_-]{60})",
            "https://developer.squareup.com/docs/build-basics/access-tokens",
        ),
        regex_detector(
            "paypal-braintree-token-v1", "Braintree access token", "braintree", "BRAINTREE_TOKEN",
            ("access_token$production", "access_token$sandbox"),
            r"(?P<secret>access_token\$(?:production|sandbox)\$[0-9a-z]{16}\$[0-9a-f]{32})",
            "https://developer.paypal.com/braintree/docs/reference/auth/overview",
        ),

        # -------------------------------------------------------------- AI/ML
        prefix_detector(
            "openai-api-key-v1", "OpenAI API key", "openai", "OPENAI_API_KEY",
            ("sk-", "sk-proj-", "sk-svcacct-"),
            r"sk-(?:proj|svcacct|admin)?-?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,}",
            "https://platform.openai.com/docs/api-reference/authentication",
        ),
        prefix_detector(
            "anthropic-api-key-v1", "Anthropic API key", "anthropic", "ANTHROPIC_API_KEY",
            ("sk-ant-",), r"sk-ant-(?:api03|admin01)-[A-Za-z0-9_-]{80,110}",
            "https://docs.anthropic.com/en/api/getting-started",
        ),
        prefix_detector(
            "huggingface-token-v1", "Hugging Face access token", "huggingface", "HUGGINGFACE_TOKEN",
            ("hf_",), r"hf_[A-Za-z0-9]{34,40}",
            "https://huggingface.co/docs/hub/security-tokens",
        ),
        prefix_detector(
            "replicate-token-v1", "Replicate API token", "replicate", "REPLICATE_TOKEN",
            ("r8_",), r"r8_[A-Za-z0-9]{40}",
            "https://replicate.com/docs/reference/http#authentication",
        ),
        prefix_detector(
            "groq-api-key-v1", "Groq API key", "groq", "GROQ_API_KEY",
            ("gsk_",), r"gsk_[A-Za-z0-9]{52}",
            "https://console.groq.com/docs/api-keys",
        ),
        prefix_detector(
            "perplexity-api-key-v1", "Perplexity API key", "perplexity", "PERPLEXITY_API_KEY",
            ("pplx-",), r"pplx-[A-Za-z0-9]{48}",
            "https://docs.perplexity.ai/guides/getting-started",
        ),

        # ------------------------------------------------------------- Comms
        prefix_detector(
            "slack-token-v1", "Slack token", "slack", "SLACK_TOKEN",
            ("xoxb-", "xoxa-", "xoxp-", "xoxr-", "xoxs-", "xapp-"),
            r"(?:xox[baprs]-[A-Za-z0-9-]{10,72}|xapp-\d-[A-Z0-9]+-\d+-[a-f0-9]{64})",
            "https://api.slack.com/authentication/token-types",
        ),
        regex_detector(
            "slack-webhook-v1", "Slack incoming webhook", "slack", "SLACK_WEBHOOK",
            ("hooks.slack.com",),
            r"(?P<secret>https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24})",
            "https://api.slack.com/messaging/webhooks",
        ),
        regex_detector(
            "sendgrid-api-key-v1", "SendGrid API key", "sendgrid", "SENDGRID_API_KEY",
            ("sg.",), r"(?P<secret>SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})",
            "https://www.twilio.com/docs/sendgrid/ui/account-and-settings/api-keys",
        ),
        prefix_detector(
            "twilio-api-key-v1", "Twilio API key SID", "twilio", "TWILIO_API_KEY",
            ("sk",), r"SK[0-9a-fA-F]{32}",
            "https://www.twilio.com/docs/iam/keys/api-key",
        ),
        prefix_detector(
            "mailgun-api-key-v1", "Mailgun API key", "mailgun", "MAILGUN_API_KEY",
            ("key-",), r"key-[0-9a-zA-Z]{32}",
            "https://documentation.mailgun.com/docs/mailgun/api-reference/authentication/",
        ),
        regex_detector(
            "mailchimp-api-key-v1", "Mailchimp API key", "mailchimp", "MAILCHIMP_API_KEY",
            ("-us",), r"(?P<secret>[0-9a-f]{32}-us[0-9]{1,2})",
            "https://mailchimp.com/developer/marketing/guides/quick-start/",
        ),
        regex_detector(
            "discord-webhook-v1", "Discord webhook", "discord", "DISCORD_WEBHOOK",
            ("discord.com/api/webhooks", "discordapp.com/api/webhooks"),
            r"(?P<secret>https://(?:ptb\.|canary\.)?disc(?:ord|ordapp)\.com/api/webhooks/[0-9]{17,20}/[A-Za-z0-9_-]{60,68})",
            "https://discord.com/developers/docs/resources/webhook",
        ),
        regex_detector(
            "telegram-bot-token-v1", "Telegram bot token", "telegram", "TELEGRAM_BOT_TOKEN",
            ("bot", "telegram"),
            r"(?:^|[^A-Za-z0-9])(?P<secret>[0-9]{8,10}:AA[A-Za-z0-9_-]{32,33})",
            "https://core.telegram.org/bots/api#authorizing-your-bot",
        ),

        # ------------------------------------------------------ Package registries
        prefix_detector(
            "npm-token-v1", "npm access token", "npm", "NPM_TOKEN",
            ("npm_",), r"npm_[A-Za-z0-9]{36}",
            "https://docs.npmjs.com/about-access-tokens",
        ),
        prefix_detector(
            "pypi-token-v1", "PyPI API token", "pypi", "PYPI_TOKEN",
            ("pypi-",), r"pypi-[A-Za-z0-9_-]{50,1000}",
            "https://pypi.org/help/#apitoken",
        ),
        prefix_detector(
            "rubygems-token-v1", "RubyGems API key", "rubygems", "RUBYGEMS_TOKEN",
            ("rubygems_",), r"rubygems_[a-f0-9]{48}",
            "https://guides.rubygems.org/api-key/",
        ),
        prefix_detector(
            "cratesio-token-v1", "crates.io API token", "cratesio", "CARGO_TOKEN",
            ("cio",), r"cio[A-Za-z0-9]{32}",
            "https://doc.rust-lang.org/cargo/reference/registry-authentication.html",
        ),
        prefix_detector(
            "nuget-api-key-v1", "NuGet API key", "nuget", "NUGET_API_KEY",
            ("oy2",), r"oy2[a-z0-9]{43}",
            "https://learn.microsoft.com/en-us/nuget/nuget-org/publish-a-package",
        ),
        prefix_detector(
            "dockerhub-pat-v1", "Docker Hub personal access token", "docker", "DOCKER_TOKEN",
            ("dckr_pat_",), r"dckr_pat_[A-Za-z0-9_-]{27}",
            "https://docs.docker.com/security/for-developers/access-tokens/",
        ),

        # ------------------------------------------------------------- Dev SaaS
        prefix_detector(
            "linear-api-key-v1", "Linear API key", "linear", "LINEAR_API_KEY",
            ("lin_api_",), r"lin_api_[A-Za-z0-9]{40}",
            "https://developers.linear.app/docs/graphql/working-with-the-graphql-api#personal-api-keys",
        ),
        prefix_detector(
            "notion-token-v1", "Notion integration token", "notion", "NOTION_TOKEN",
            ("ntn_", "secret_"), r"(?:ntn_[A-Za-z0-9]{40,48}|secret_[A-Za-z0-9]{43})",
            "https://developers.notion.com/docs/authorization",
        ),
        prefix_detector(
            "airtable-pat-v1", "Airtable personal access token", "airtable", "AIRTABLE_TOKEN",
            ("pat",), r"pat[A-Za-z0-9]{14}\.[A-Za-z0-9]{64}",
            "https://airtable.com/developers/web/guides/personal-access-tokens",
        ),
        prefix_detector(
            "postman-api-key-v1", "Postman API key", "postman", "POSTMAN_API_KEY",
            ("pmak-",), r"PMAK-[a-f0-9]{24}-[a-f0-9]{34}",
            "https://learning.postman.com/docs/developer/postman-api/authentication/",
        ),
        prefix_detector(
            "figma-token-v1", "Figma personal access token", "figma", "FIGMA_TOKEN",
            ("figd_",), r"figd_[A-Za-z0-9_-]{40,64}",
            "https://www.figma.com/developers/api#access-tokens",
        ),
        prefix_detector(
            "atlassian-api-token-v1", "Atlassian API token", "atlassian", "ATLASSIAN_TOKEN",
            ("atatt",), r"ATATT[A-Za-z0-9_\-=]{180,220}",
            "https://support.atlassian.com/atlassian-account/docs/manage-api-tokens-for-your-atlassian-account/",
        ),
        prefix_detector(
            "shopify-token-v1", "Shopify access token", "shopify", "SHOPIFY_TOKEN",
            ("shpat_", "shpss_", "shpca_", "shppa_"), r"shp(?:at|ss|ca|pa)_[a-fA-F0-9]{32}",
            "https://shopify.dev/docs/apps/build/authentication-authorization/access-tokens",
        ),
        prefix_detector(
            "hubspot-token-v1", "HubSpot private app token", "hubspot", "HUBSPOT_TOKEN",
            ("pat-na", "pat-eu"), r"pat-(?:na|eu)[0-9]-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            "https://developers.hubspot.com/docs/guides/apps/private-apps/overview",
        ),
        prefix_detector(
            "supabase-token-v1", "Supabase access token", "supabase", "SUPABASE_TOKEN",
            ("sbp_",), r"sbp_[a-f0-9]{40}",
            "https://supabase.com/docs/reference/api/introduction",
        ),
        prefix_detector(
            "sentry-token-v1", "Sentry auth token", "sentry", "SENTRY_TOKEN",
            ("sntrys_",), r"sntrys_[A-Za-z0-9+/=_]{60,220}",
            "https://docs.sentry.io/account/auth-tokens/",
        ),
        prefix_detector(
            "circleci-pat-v1", "CircleCI personal access token", "circleci", "CIRCLECI_TOKEN",
            ("ccipat_",), r"CCIPAT_[A-Za-z0-9]{22}_[A-Za-z0-9]{40}",
            "https://circleci.com/docs/managing-api-tokens/",
        ),

        # --------------------------------------------------- Database URIs / generic
        regex_detector(
            "database-connection-uri-v1", "Database connection URI with password", "database", "DB_CONNECTION_STRING",
            ("postgres", "postgresql", "mysql", "mongodb", "redis"),
            r"(?P<secret>(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|rediss?)://[A-Za-z0-9_.-]+:[^\s@'\"/]{3,}@[A-Za-z0-9_.-]+)",
            "https://www.rfc-editor.org/rfc/rfc3986#section-3.2.1",
            description="A database URI carrying an inline password (userinfo component).",
            span=512,
        ),
        regex_detector(
            "jwt-v1", "JSON Web Token", "generic", "JWT",
            ("eyj",),
            r"(?P<secret>eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})",
            "https://www.rfc-editor.org/rfc/rfc7519",
            description="A three-part base64url JWT. Not every JWT is a secret; treat with FP care.",
        ),
        regex_detector(
            "private-key-v1", "Private key", "generic", "PRIVATE_KEY",
            ("-----begin", "private key"),
            r"(?P<secret>-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----[\s\S]{50,}?-----END (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----)",
            "https://www.rfc-editor.org/rfc/rfc7468",
            description="A PEM-encoded private key block (RSA/EC/DSA/OpenSSH/PGP/encrypted).",
            span=8192,
        ),

        # ----------------------------------------------------- second batch
        prefix_detector(
            "google-oauth-client-secret-v1", "Google OAuth client secret", "gcp", "GCP_OAUTH_CLIENT_SECRET",
            ("gocspx-",), r"GOCSPX-[A-Za-z0-9_-]{28}",
            "https://developers.google.com/identity/protocols/oauth2",
        ),
        prefix_detector(
            "dropbox-access-token-v1", "Dropbox access token", "dropbox", "DROPBOX_TOKEN",
            ("sl.",), r"sl\.[A-Za-z0-9_-]{130,152}",
            "https://developers.dropbox.com/oauth-guide",
        ),
        prefix_detector(
            "pulumi-access-token-v1", "Pulumi access token", "pulumi", "PULUMI_TOKEN",
            ("pul-",), r"pul-[a-f0-9]{40}",
            "https://www.pulumi.com/docs/pulumi-cloud/access-management/access-tokens/",
        ),
        prefix_detector(
            "planetscale-token-v1", "PlanetScale token", "planetscale", "PLANETSCALE_TOKEN",
            ("pscale_tkn_", "pscale_pw_"), r"pscale_(?:tkn|pw)_[A-Za-z0-9_=.-]{32,64}",
            "https://planetscale.com/docs/concepts/service-tokens",
        ),
        prefix_detector(
            "resend-api-key-v1", "Resend API key", "resend", "RESEND_API_KEY",
            ("re_",), r"re_[A-Za-z0-9_]{20,40}",
            "https://resend.com/docs/api-reference/introduction",
        ),
        prefix_detector(
            "plaid-access-token-v1", "Plaid access token", "plaid", "PLAID_TOKEN",
            ("access-sandbox-", "access-development-", "access-production-"),
            r"access-(?:sandbox|development|production)-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            "https://plaid.com/docs/api/tokens/",
        ),
        prefix_detector(
            "fireworks-api-key-v1", "Fireworks AI API key", "fireworks", "FIREWORKS_API_KEY",
            ("fw_",), r"fw_[A-Za-z0-9]{24,32}",
            "https://docs.fireworks.ai/getting-started/quickstart",
        ),
        prefix_detector(
            "render-api-key-v1", "Render API key", "render", "RENDER_API_KEY",
            ("rnd_",), r"rnd_[A-Za-z0-9]{20,30}",
            "https://render.com/docs/api",
        ),
        prefix_detector(
            "launchdarkly-api-token-v1", "LaunchDarkly API access token", "launchdarkly", "LAUNCHDARKLY_TOKEN",
            ("api-",), r"api-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            "https://docs.launchdarkly.com/home/account-security/api-access-tokens",
        ),
        regex_detector(
            "cloudinary-url-v1", "Cloudinary URL", "cloudinary", "CLOUDINARY_URL",
            ("cloudinary://",),
            r"(?P<secret>cloudinary://[0-9]{12,20}:[A-Za-z0-9_-]{20,40}@[A-Za-z0-9_-]+)",
            "https://cloudinary.com/documentation/how_to_integrate_cloudinary",
        ),
        regex_detector(
            "asana-pat-v1", "Asana personal access token", "asana", "ASANA_TOKEN",
            ("1/",),
            r"(?:^|[^0-9])(?P<secret>1/[0-9]{16}:[0-9a-f]{32})",
            "https://developers.asana.com/docs/personal-access-token",
        ),
        regex_detector(
            "sentry-dsn-v1", "Sentry DSN", "sentry", "SENTRY_DSN",
            ("sentry.io", "ingest."),
            r"(?P<secret>https://[0-9a-f]{32}@[A-Za-z0-9.-]*sentry[A-Za-z0-9.-]*/[0-9]+)",
            "https://docs.sentry.io/concepts/key-terms/dsn-explainer/",
            description="A Sentry DSN embeds the project's public key.",
        ),

        # ----------------------------------------------------- third batch
        prefix_detector(
            "gitlab-runner-token-v1", "GitLab runner authentication token", "gitlab", "GITLAB_RUNNER_TOKEN",
            ("glrt-",), r"glrt-[A-Za-z0-9_-]{20}",
            "https://docs.gitlab.com/ee/security/token_overview.html",
        ),
        prefix_detector(
            "gitlab-pipeline-trigger-token-v1", "GitLab pipeline trigger token", "gitlab", "GITLAB_PIPELINE_TRIGGER_TOKEN",
            ("glptt-",), r"glptt-[0-9a-f]{40}",
            "https://docs.gitlab.com/ee/ci/triggers/",
        ),
        prefix_detector(
            "discord-bot-token-v1", "Discord bot token", "discord", "DISCORD_BOT_TOKEN",
            ("discord",), r"[MNO][A-Za-z0-9_-]{23,25}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,38}",
            "https://discord.com/developers/docs/reference#authentication",
            description="A Discord bot token: three base64url segments (id.timestamp.hmac).",
        ),
        prefix_detector(
            "xai-api-key-v1", "xAI API key", "xai", "XAI_API_KEY",
            ("xai-",), r"xai-[A-Za-z0-9]{80}",
            "https://docs.x.ai/docs/overview",
        ),
        prefix_detector(
            "openrouter-api-key-v1", "OpenRouter API key", "openrouter", "OPENROUTER_API_KEY",
            ("sk-or-v1-",), r"sk-or-v1-[a-f0-9]{64}",
            "https://openrouter.ai/docs/api-reference/authentication",
        ),
        prefix_detector(
            "tailscale-key-v1", "Tailscale key", "tailscale", "TAILSCALE_KEY",
            ("tskey-",), r"tskey-(?:auth|api|client|scim)-[A-Za-z0-9]{5,}-[A-Za-z0-9]{30,}",
            "https://tailscale.com/kb/1085/auth-keys",
        ),
        prefix_detector(
            "brevo-api-key-v1", "Brevo (Sendinblue) API key", "brevo", "BREVO_API_KEY",
            ("xkeysib-",), r"xkeysib-[a-f0-9]{64}-[A-Za-z0-9]{16}",
            "https://developers.brevo.com/docs/getting-started",
        ),
        prefix_detector(
            "dynatrace-token-v1", "Dynatrace token", "dynatrace", "DYNATRACE_TOKEN",
            ("dt0",), r"dt0[a-z]01\.[A-Z0-9]{24}\.[A-Z0-9]{64}",
            "https://docs.dynatrace.com/docs/manage/access-control/access-tokens",
        ),
        prefix_detector(
            "prefect-api-key-v1", "Prefect Cloud API key", "prefect", "PREFECT_API_KEY",
            ("pnu_", "pnb_"), r"pn[ub]_[A-Za-z0-9]{36}",
            "https://docs.prefect.io/v3/manage/cloud/manage-users/api-keys",
        ),
        prefix_detector(
            "adafruit-io-key-v1", "Adafruit IO key", "adafruit", "ADAFRUIT_IO_KEY",
            ("aio_",), r"aio_[A-Za-z0-9]{28}",
            "https://io.adafruit.com/api/docs/#authentication",
        ),
        prefix_detector(
            "shippo-api-token-v1", "Shippo API token", "shippo", "SHIPPO_TOKEN",
            ("shippo_",), r"shippo_(?:live|test)_[0-9a-f]{40}",
            "https://docs.goshippo.com/docs/api/authentication",
        ),
        prefix_detector(
            "frameio-token-v1", "Frame.io developer token", "frameio", "FRAMEIO_TOKEN",
            ("fio-u-",), r"fio-u-[A-Za-z0-9_-]{64}",
            "https://developer.frame.io/docs/getting-started/authentication",
        ),
        prefix_detector(
            "duffel-token-v1", "Duffel access token", "duffel", "DUFFEL_TOKEN",
            ("duffel_test_", "duffel_live_"), r"duffel_(?:test|live)_[A-Za-z0-9_-]{43}",
            "https://duffel.com/docs/guides/getting-started-with-flights",
        ),
        prefix_detector(
            "easypost-api-key-v1", "EasyPost API key", "easypost", "EASYPOST_API_KEY",
            ("ezak", "eztk"), r"EZ[AT]K[A-Za-z0-9]{54}",
            "https://docs.easypost.com/docs/authentication",
        ),
        regex_detector(
            "firebase-fcm-legacy-server-key-v1", "Firebase Cloud Messaging legacy server key", "firebase", "FCM_SERVER_KEY",
            ("apa91b",),
            r"(?P<secret>AAAA[A-Za-z0-9_-]{7}:APA91b[A-Za-z0-9_-]{130,160})",
            "https://firebase.google.com/docs/cloud-messaging/auth-server",
            description="A legacy FCM server key embeds the ':APA91b' registration marker.",
        ),
        regex_detector(
            "zapier-webhook-v1", "Zapier webhook URL", "zapier", "ZAPIER_WEBHOOK",
            ("hooks.zapier.com",),
            r"(?P<secret>https://hooks\.zapier\.com/hooks/catch/[0-9]+/[A-Za-z0-9]+/?)",
            "https://help.zapier.com/hc/en-us/articles/8496288690317",
        ),
        regex_detector(
            "microsoft-teams-webhook-v1", "Microsoft Teams incoming webhook", "microsoft", "TEAMS_WEBHOOK",
            ("webhook.office.com",),
            r"(?P<secret>https://[A-Za-z0-9.-]+\.webhook\.office\.com/webhookb2/[0-9a-fA-F-]{36}@[0-9a-fA-F-]{36}/IncomingWebhook/[0-9a-f]{32}/[0-9a-fA-F-]{36})",
            "https://learn.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook",
        ),

        # ----------------------------------------------------- fourth batch
        prefix_detector(
            "alibaba-access-key-id-v1", "Alibaba Cloud AccessKey ID", "alibaba", "ALIBABA_ACCESS_KEY_ID",
            ("ltai",), r"LTAI[A-Za-z0-9]{12,20}",
            "https://www.alibabacloud.com/help/en/ram/user-guide/create-an-accesskey-pair",
            description="An Alibaba Cloud AccessKey identifier (pairs with a secret).",
        ),
        prefix_detector(
            "tencent-secret-id-v1", "Tencent Cloud SecretId", "tencent", "TENCENT_SECRET_ID",
            ("akid",), r"AKID[A-Za-z0-9]{13,40}",
            "https://www.tencentcloud.com/document/product/598/34228",
            description="A Tencent Cloud API SecretId (pairs with a SecretKey).",
        ),
        prefix_detector(
            "pinecone-api-key-v1", "Pinecone API key", "pinecone", "PINECONE_API_KEY",
            ("pcsk_",), r"pcsk_[A-Za-z0-9_]{40,}",
            "https://docs.pinecone.io/guides/get-started/authentication",
        ),
        prefix_detector(
            "langsmith-api-key-v1", "LangSmith API key", "langsmith", "LANGSMITH_API_KEY",
            ("lsv2_pt_", "lsv2_sk_"), r"lsv2_(?:pt|sk)_[A-Za-z0-9]{32,}_[A-Za-z0-9]{10,}",
            "https://docs.smith.langchain.com/administration/how_to_guides/organization_management/create_account_api_key",
        ),
        prefix_detector(
            "sourcegraph-token-v1", "Sourcegraph access token", "sourcegraph", "SOURCEGRAPH_TOKEN",
            ("sgp_",), r"sgp_(?:[A-Fa-f0-9]{16}_|local_)?[A-Fa-f0-9]{40}",
            "https://sourcegraph.com/docs/cli/how-tos/creating_an_access_token",
        ),
        prefix_detector(
            "buildkite-agent-token-v1", "Buildkite agent token", "buildkite", "BUILDKITE_AGENT_TOKEN",
            ("bkua_",), r"bkua_[a-z0-9]{40}",
            "https://buildkite.com/docs/agent/v3/tokens",
        ),
        regex_detector(
            "newrelic-license-key-v1", "New Relic license key", "newrelic", "NEWRELIC_LICENSE_KEY",
            ("nral",), r"(?P<secret>[A-Fa-f0-9]{36}NRAL)",
            "https://docs.newrelic.com/docs/apis/intro-apis/new-relic-api-keys/",
            description="A New Relic license key ends with the 'NRAL' marker.",
        ),
        prefix_detector(
            "contentful-pat-v1", "Contentful personal access token", "contentful", "CONTENTFUL_TOKEN",
            ("cfpat-",), r"CFPAT-[A-Za-z0-9_-]{43}",
            "https://www.contentful.com/developers/docs/references/content-management-api/#/reference/personal-access-tokens",
        ),
        prefix_detector(
            "woocommerce-key-v1", "WooCommerce API key", "woocommerce", "WOOCOMMERCE_KEY",
            ("ck_", "cs_"), r"(?:ck|cs)_[a-f0-9]{40}",
            "https://woocommerce.github.io/woocommerce-rest-api-docs/#authentication",
        ),
        prefix_detector(
            "artifactory-api-key-v1", "JFrog Artifactory API key", "jfrog", "ARTIFACTORY_API_KEY",
            ("akcp",), r"AKCp[A-Za-z0-9]{64,74}",
            "https://jfrog.com/help/r/jfrog-platform-administration-documentation/api-key",
        ),
        prefix_detector(
            "sonarqube-token-v1", "SonarQube/SonarCloud token", "sonar", "SONAR_TOKEN",
            ("sqp_", "sqa_", "squ_"), r"sq[apu]_[a-f0-9]{40}",
            "https://docs.sonarsource.com/sonarqube/latest/user-guide/user-account/generating-and-using-tokens/",
        ),
        prefix_detector(
            "clickup-token-v1", "ClickUp personal token", "clickup", "CLICKUP_TOKEN",
            ("pk_",), r"pk_[0-9]{6,9}_[A-Z0-9]{32}",
            "https://developer.clickup.com/docs/authentication",
        ),
        prefix_detector(
            "stytch-secret-v1", "Stytch secret", "stytch", "STYTCH_SECRET",
            ("secret-live-", "secret-test-"), r"secret-(?:live|test)-[A-Za-z0-9=_-]{36,}",
            "https://stytch.com/docs/api/getting-started",
        ),
        prefix_detector(
            "ory-pat-v1", "Ory personal access token", "ory", "ORY_TOKEN",
            ("ory_pat_", "ory_st_"), r"ory_(?:pat|st)_[A-Za-z0-9_-]{32,}",
            "https://www.ory.sh/docs/hydra/self-hosted/secrets-key-rotation",
        ),
        prefix_detector(
            "xata-api-key-v1", "Xata API key", "xata", "XATA_API_KEY",
            ("xau_",), r"xau_[A-Za-z0-9]{37}",
            "https://xata.io/docs/rest-api/authentication",
        ),
        prefix_detector(
            "jina-api-key-v1", "Jina AI API key", "jina", "JINA_API_KEY",
            ("jina_",), r"jina_[A-Za-z0-9_-]{32,}",
            "https://jina.ai/",
        ),
        regex_detector(
            "flutterwave-secret-key-v1", "Flutterwave secret key", "flutterwave", "FLUTTERWAVE_SECRET_KEY",
            ("flwseck-",), r"(?P<secret>FLWSECK-[0-9a-f]{32}-X)",
            "https://developer.flutterwave.com/docs/api-keys",
        ),
        prefix_detector(
            "posthog-api-key-v1", "PostHog API key", "posthog", "POSTHOG_API_KEY",
            ("phc_", "phx_"), r"ph[cx]_[A-Za-z0-9]{43}",
            "https://posthog.com/docs/api",
        ),
        prefix_detector(
            "calcom-api-key-v1", "Cal.com API key", "calcom", "CALCOM_API_KEY",
            ("cal_live_", "cal_test_"), r"cal_(?:live|test)_[a-f0-9]{32,}",
            "https://cal.com/docs/api-reference/v2/introduction",
        ),
        prefix_detector(
            "typeform-pat-v1", "Typeform personal access token", "typeform", "TYPEFORM_TOKEN",
            ("tfp_",), r"tfp_[A-Za-z0-9_-]{44,}",
            "https://www.typeform.com/developers/get-started/personal-access-token/",
        ),
        regex_detector(
            "heroku-api-key-v1", "Heroku API key", "heroku", "HEROKU_API_KEY",
            ("heroku",),
            r"(?P<secret>[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})",
            "https://devcenter.heroku.com/articles/platform-api-quickstart",
            description="A Heroku API key is a UUID; routed only near a 'heroku' keyword.",
            span=256,
        ),

        # -------------------------------------------- fifth batch (labelled)
        # Providers whose secret has no distinctive shape: anchored to the
        # documented config label so a bare token never matches on its own.
        labeled_secret_detector(
            "datadog-api-key-v1", "Datadog API key", "datadog", "DATADOG_API_KEY",
            ("datadog", "dd_api", "dd-api"), r"(?:datadog|dd)[_-]?api[_-]?key",
            r"[a-f0-9]{32}", "https://docs.datadoghq.com/account_management/api-app-keys/",
        ),
        labeled_secret_detector(
            "datadog-app-key-v1", "Datadog application key", "datadog", "DATADOG_APP_KEY",
            ("datadog", "dd_app", "dd-app"), r"(?:datadog|dd)[_-]?app(?:lication)?[_-]?key",
            r"[a-f0-9]{40}", "https://docs.datadoghq.com/account_management/api-app-keys/",
        ),
        labeled_secret_detector(
            "algolia-admin-key-v1", "Algolia admin API key", "algolia", "ALGOLIA_ADMIN_KEY",
            ("algolia",), r"algolia[_-]?(?:admin[_-]?)?(?:api[_-]?)?key",
            r"[a-f0-9]{32}", "https://www.algolia.com/doc/guides/security/api-keys/",
        ),
        labeled_secret_detector(
            "mixpanel-secret-v1", "Mixpanel API secret", "mixpanel", "MIXPANEL_SECRET",
            ("mixpanel",), r"mixpanel[_-]?(?:api[_-]?)?secret",
            r"[a-f0-9]{32}", "https://developer.mixpanel.com/reference/authentication",
        ),
        labeled_secret_detector(
            "amplitude-api-key-v1", "Amplitude API key", "amplitude", "AMPLITUDE_API_KEY",
            ("amplitude",), r"amplitude[_-]?(?:api[_-]?)?key",
            r"[a-f0-9]{32}", "https://www.docs.developers.amplitude.com/analytics/apis/http-v2-api/",
        ),
        labeled_secret_detector(
            "fastly-api-token-v1", "Fastly API token", "fastly", "FASTLY_API_TOKEN",
            ("fastly",), r"fastly[_-]?(?:api[_-]?)?(?:token|key)",
            r"[A-Za-z0-9_-]{32}", "https://docs.fastly.com/en/guides/using-api-tokens",
        ),
        labeled_secret_detector(
            "cloudflare-api-token-v1", "Cloudflare API token", "cloudflare", "CLOUDFLARE_API_TOKEN",
            ("cloudflare", "cf_api", "cf-api"), r"(?:cloudflare|cf)[_-]?api[_-]?token",
            r"[A-Za-z0-9_-]{40}", "https://developers.cloudflare.com/fundamentals/api/get-started/create-token/",
        ),
        labeled_secret_detector(
            "honeycomb-api-key-v1", "Honeycomb API key", "honeycomb", "HONEYCOMB_API_KEY",
            ("honeycomb",), r"honeycomb[_-]?(?:api[_-]?)?key",
            r"[a-f0-9]{32}", "https://docs.honeycomb.io/configure/environments/manage-api-keys/",
        ),
        labeled_secret_detector(
            "rollbar-access-token-v1", "Rollbar access token", "rollbar", "ROLLBAR_TOKEN",
            ("rollbar",), r"rollbar[_-]?(?:access[_-]?)?token",
            r"[a-f0-9]{32}", "https://docs.rollbar.com/reference/getting-started-1",
        ),
        labeled_secret_detector(
            "bugsnag-api-key-v1", "Bugsnag API key", "bugsnag", "BUGSNAG_API_KEY",
            ("bugsnag",), r"bugsnag[_-]?(?:api[_-]?)?key",
            r"[a-f0-9]{32}", "https://docs.bugsnag.com/api/",
        ),
        labeled_secret_detector(
            "sparkpost-api-key-v1", "SparkPost API key", "sparkpost", "SPARKPOST_API_KEY",
            ("sparkpost",), r"sparkpost[_-]?(?:api[_-]?)?key",
            r"[a-f0-9]{40}", "https://developers.sparkpost.com/api/#header-authentication",
        ),
        labeled_secret_detector(
            "postmark-server-token-v1", "Postmark server token", "postmark", "POSTMARK_TOKEN",
            ("postmark",), r"postmark[_-]?(?:server[_-]?)?token",
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            "https://postmarkapp.com/developer/api/overview#authentication",
        ),
        labeled_secret_detector(
            "snyk-api-token-v1", "Snyk API token", "snyk", "SNYK_TOKEN",
            ("snyk",), r"snyk[_-]?(?:api[_-]?)?token",
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            "https://docs.snyk.io/snyk-api/authentication-for-api",
        ),
        labeled_secret_detector(
            "opsgenie-api-key-v1", "Opsgenie API key", "opsgenie", "OPSGENIE_API_KEY",
            ("opsgenie",), r"opsgenie[_-]?(?:api[_-]?)?key",
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            "https://support.atlassian.com/opsgenie/docs/api-key-management/",
        ),
        labeled_secret_detector(
            "deepgram-api-key-v1", "Deepgram API key", "deepgram", "DEEPGRAM_API_KEY",
            ("deepgram",), r"deepgram[_-]?(?:api[_-]?)?key",
            r"[a-f0-9]{40}", "https://developers.deepgram.com/docs/create-additional-api-keys",
        ),
        labeled_secret_detector(
            "cohere-api-key-v1", "Cohere API key", "cohere", "COHERE_API_KEY",
            ("cohere",), r"cohere[_-]?(?:api[_-]?)?key",
            r"[A-Za-z0-9]{40}", "https://docs.cohere.com/reference/about",
        ),
        labeled_secret_detector(
            "mistral-api-key-v1", "Mistral API key", "mistral", "MISTRAL_API_KEY",
            ("mistral",), r"mistral[_-]?(?:api[_-]?)?key",
            r"[A-Za-z0-9]{32}", "https://docs.mistral.ai/getting-started/quickstart/",
        ),
        labeled_secret_detector(
            "elevenlabs-api-key-v1", "ElevenLabs API key", "elevenlabs", "ELEVENLABS_API_KEY",
            ("elevenlabs", "eleven_labs", "xi_api", "xi-api"),
            r"(?:elevenlabs|eleven[_-]?labs|xi)[_-]?api[_-]?key",
            r"[a-f0-9]{32}", "https://elevenlabs.io/docs/api-reference/authentication",
        ),
        labeled_secret_detector(
            "togetherai-api-key-v1", "Together AI API key", "togetherai", "TOGETHER_API_KEY",
            ("together",), r"together[_-]?(?:ai[_-]?)?(?:api[_-]?)?key",
            r"[a-f0-9]{64}", "https://docs.together.ai/reference/authentication-1",
        ),
        labeled_secret_detector(
            "trello-api-key-v1", "Trello API key", "trello", "TRELLO_API_KEY",
            ("trello",), r"trello[_-]?(?:api[_-]?)?key",
            r"[0-9a-f]{32}", "https://developer.atlassian.com/cloud/trello/guides/rest-api/api-introduction/",
        ),

        # ----------------------------------------------------- sixth batch
        prefix_detector(
            "neon-api-key-v1", "Neon API key", "neon", "NEON_API_KEY",
            ("napi_",), r"napi_[a-z0-9]{30,}",
            "https://neon.tech/docs/manage/api-keys",
        ),
        prefix_detector(
            "deno-deploy-token-v1", "Deno Deploy access token", "deno", "DENO_DEPLOY_TOKEN",
            ("ddp_",), r"ddp_[A-Za-z0-9]{40,}",
            "https://docs.deno.com/deploy/api/rest/",
        ),
        prefix_detector(
            "bitbucket-access-token-v1", "Bitbucket access token", "bitbucket", "BITBUCKET_TOKEN",
            ("atbb",), r"ATBB[A-Za-z0-9]{32,}",
            "https://support.atlassian.com/bitbucket-cloud/docs/repository-access-tokens/",
        ),
        prefix_detector(
            "pubnub-key-v1", "PubNub publish/subscribe key", "pubnub", "PUBNUB_KEY",
            ("pub-c-", "sub-c-"),
            r"(?:pub|sub)-c-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            "https://www.pubnub.com/docs/general/setup/account-setup",
        ),
        labeled_secret_detector(
            "okta-api-token-v1", "Okta API token", "okta", "OKTA_API_TOKEN",
            ("okta",), r"okta[_-]?(?:api[_-]?)?token",
            r"00[A-Za-z0-9_-]{40}", "https://developer.okta.com/docs/guides/create-an-api-token/",
        ),
        labeled_secret_detector(
            "pusher-secret-v1", "Pusher Channels secret", "pusher", "PUSHER_SECRET",
            ("pusher",), r"pusher[_-]?(?:app[_-]?)?secret",
            r"[a-f0-9]{20,32}", "https://pusher.com/docs/channels/using_channels/authorized-connections/",
        ),
        labeled_secret_detector(
            "twilio-auth-token-v1", "Twilio auth token", "twilio", "TWILIO_AUTH_TOKEN",
            ("twilio",), r"twilio[_-]?auth[_-]?token",
            r"[a-f0-9]{32}", "https://www.twilio.com/docs/iam/access-tokens",
        ),
        labeled_secret_detector(
            "plivo-auth-token-v1", "Plivo auth token", "plivo", "PLIVO_AUTH_TOKEN",
            ("plivo",), r"plivo[_-]?auth[_-]?token",
            r"[A-Za-z0-9]{40}", "https://www.plivo.com/docs/sms/concepts/authentication/",
        ),
        labeled_secret_detector(
            "meilisearch-master-key-v1", "Meilisearch master/API key", "meilisearch", "MEILISEARCH_KEY",
            ("meili", "meilisearch"), r"meili(?:search)?[_-]?(?:master[_-]?|api[_-]?)?key",
            r"[A-Za-z0-9]{32,}", "https://www.meilisearch.com/docs/learn/security/master_api_keys",
        ),
        labeled_secret_detector(
            "typesense-api-key-v1", "Typesense API key", "typesense", "TYPESENSE_KEY",
            ("typesense",), r"typesense[_-]?(?:api[_-]?)?key",
            r"[A-Za-z0-9]{32,}", "https://typesense.org/docs/guide/",
        ),

        # --------------------------------------------------- seventh batch
        prefix_detector(
            "netlify-token-v1", "Netlify personal access token", "netlify", "NETLIFY_TOKEN",
            ("nfp_",), r"nfp_[A-Za-z0-9]{36,}",
            "https://docs.netlify.com/api/get-started/#authentication",
        ),
        labeled_secret_detector(
            "wandb-api-key-v1", "Weights & Biases API key", "wandb", "WANDB_API_KEY",
            ("wandb",), r"wandb[_-]?(?:api[_-]?)?key",
            r"[a-f0-9]{40}", "https://docs.wandb.ai/guides/track/public-api-guide",
        ),
        labeled_secret_detector(
            "assemblyai-api-key-v1", "AssemblyAI API key", "assemblyai", "ASSEMBLYAI_API_KEY",
            ("assemblyai",), r"assemblyai[_-]?(?:api[_-]?)?key",
            r"[a-f0-9]{32}", "https://www.assemblyai.com/docs/api-reference/overview",
        ),
        labeled_secret_detector(
            "mailjet-api-key-v1", "Mailjet API key", "mailjet", "MAILJET_KEY",
            ("mailjet",), r"mailjet[_-]?(?:api[_-]?)?(?:key|secret)",
            r"[a-f0-9]{32}", "https://dev.mailjet.com/email/guides/",
        ),
        labeled_secret_detector(
            "klaviyo-private-key-v1", "Klaviyo private API key", "klaviyo", "KLAVIYO_KEY",
            ("klaviyo",), r"klaviyo[_-]?(?:private[_-]?|api[_-]?)?key",
            r"pk_[a-f0-9]{34}", "https://developers.klaviyo.com/en/docs/authenticate_",
        ),
        labeled_secret_detector(
            "vultr-api-key-v1", "Vultr API key", "vultr", "VULTR_API_KEY",
            ("vultr",), r"vultr[_-]?(?:api[_-]?)?key",
            r"[A-Z0-9]{36}", "https://www.vultr.com/api/",
        ),
        labeled_secret_detector(
            "linode-token-v1", "Linode API token", "linode", "LINODE_TOKEN",
            ("linode",), r"linode[_-]?(?:api[_-]?)?(?:token|key)",
            r"[a-f0-9]{64}", "https://techdocs.akamai.com/linode-api/reference/get-started",
        ),
        labeled_secret_detector(
            "hetzner-api-token-v1", "Hetzner Cloud API token", "hetzner", "HETZNER_TOKEN",
            ("hetzner",), r"hetzner[_-]?(?:api[_-]?)?token",
            r"[A-Za-z0-9]{64}", "https://docs.hetzner.cloud/",
        ),
        labeled_secret_detector(
            "scaleway-secret-key-v1", "Scaleway secret key", "scaleway", "SCALEWAY_SECRET_KEY",
            ("scaleway", "scw"), r"(?:scaleway|scw)[_-]?secret[_-]?key",
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            "https://www.scaleway.com/en/docs/identity-and-access-management/iam/how-to/create-api-keys/",
        ),
        labeled_secret_detector(
            "gitea-token-v1", "Gitea access token", "gitea", "GITEA_TOKEN",
            ("gitea",), r"gitea[_-]?(?:access[_-]?)?token",
            r"[0-9a-f]{40}", "https://docs.gitea.com/development/api-usage",
        ),
        labeled_secret_detector(
            "codecov-token-v1", "Codecov upload token", "codecov", "CODECOV_TOKEN",
            ("codecov",), r"codecov[_-]?(?:upload[_-]?)?token",
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            "https://docs.codecov.com/docs/codecov-uploader",
        ),
        labeled_secret_detector(
            "consul-token-v1", "HashiCorp Consul token", "hashicorp", "CONSUL_TOKEN",
            ("consul",), r"consul[_-]?(?:acl[_-]?)?token",
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            "https://developer.hashicorp.com/consul/docs/security/acl",
        ),
        labeled_secret_detector(
            "nomad-token-v1", "HashiCorp Nomad token", "hashicorp", "NOMAD_TOKEN",
            ("nomad",), r"nomad[_-]?(?:acl[_-]?)?token",
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            "https://developer.hashicorp.com/nomad/docs/concepts/acl",
        ),
        labeled_secret_detector(
            "mandrill-api-key-v1", "Mandrill API key", "mandrill", "MANDRILL_API_KEY",
            ("mandrill",), r"mandrill[_-]?(?:api[_-]?)?key",
            r"[A-Za-z0-9_-]{22}", "https://mailchimp.com/developer/transactional/api/",
        ),

        # ---------------------------------------------------- eighth batch
        prefix_detector(
            "razorpay-key-id-v1", "Razorpay key ID", "razorpay", "RAZORPAY_KEY_ID",
            ("rzp_live_", "rzp_test_"), r"rzp_(?:live|test)_[A-Za-z0-9]{14}",
            "https://razorpay.com/docs/api/authentication/",
            description="A Razorpay key identifier (pairs with a key secret).",
        ),
        labeled_secret_detector(
            "uptimerobot-api-key-v1", "UptimeRobot API key", "uptimerobot", "UPTIMEROBOT_API_KEY",
            ("uptimerobot", "uptime_robot"), r"uptime[_-]?robot[_-]?(?:api[_-]?)?key",
            r"u[0-9]{6,8}-[a-f0-9]{32}", "https://uptimerobot.com/api/",
        ),
        labeled_secret_detector(
            "ghost-admin-key-v1", "Ghost Admin API key", "ghost", "GHOST_ADMIN_KEY",
            ("ghost",), r"ghost[_-]?(?:admin[_-]?)?(?:api[_-]?)?key",
            r"[0-9a-f]{24}:[0-9a-f]{64}", "https://ghost.org/docs/admin-api/#token-authentication",
        ),
        labeled_secret_detector(
            "airbrake-api-key-v1", "Airbrake project key", "airbrake", "AIRBRAKE_API_KEY",
            ("airbrake",), r"airbrake[_-]?(?:project[_-]?|api[_-]?)?key",
            r"[a-f0-9]{32}", "https://docs.airbrake.io/docs/devops-tools/api/",
        ),
        labeled_secret_detector(
            "splunk-hec-token-v1", "Splunk HEC token", "splunk", "SPLUNK_HEC_TOKEN",
            ("splunk",), r"splunk[_-]?(?:hec[_-]?)?token",
            r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}",
            "https://docs.splunk.com/Documentation/Splunk/latest/Data/UsetheHTTPEventCollector",
        ),
        labeled_secret_detector(
            "pagerduty-api-token-v1", "PagerDuty API token", "pagerduty", "PAGERDUTY_TOKEN",
            ("pagerduty",), r"pagerduty[_-]?(?:api[_-]?)?token",
            r"[A-Za-z0-9_+-]{20}", "https://developer.pagerduty.com/docs/authentication",
        ),
        labeled_secret_detector(
            "mollie-api-key-v1", "Mollie API key", "mollie", "MOLLIE_API_KEY",
            ("mollie",), r"mollie[_-]?(?:api[_-]?)?key",
            r"(?:live|test)_[A-Za-z0-9]{30}", "https://docs.mollie.com/reference/authentication",
        ),
        labeled_secret_detector(
            "gocardless-token-v1", "GoCardless access token", "gocardless", "GOCARDLESS_TOKEN",
            ("gocardless",), r"gocardless[_-]?(?:access[_-]?)?token",
            r"(?:live|sandbox)_[A-Za-z0-9_=-]{40}", "https://developer.gocardless.com/api-reference",
        ),

        # ----------------------------------------------------- ninth batch
        prefix_detector(
            "axiom-token-v1", "Axiom API token", "axiom", "AXIOM_TOKEN",
            ("xaat-",), r"xaat-[A-Za-z0-9-]{36,}",
            "https://axiom.co/docs/reference/tokens",
        ),
        prefix_detector(
            "llamacloud-api-key-v1", "LlamaCloud API key", "llamacloud", "LLAMACLOUD_API_KEY",
            ("llx-",), r"llx-[A-Za-z0-9]{40,}",
            "https://docs.cloud.llamaindex.ai/",
        ),
        regex_detector(
            "azure-entra-client-secret-v1", "Microsoft Entra client secret", "azure", "AZURE_ENTRA_CLIENT_SECRET",
            ("q~",),
            r"(?:^|[^A-Za-z0-9_~.-])(?P<secret>[A-Za-z0-9_~.-]{3}[0-9]Q~[A-Za-z0-9_~.-]{31,34})(?:$|[^A-Za-z0-9_~.-])",
            "https://learn.microsoft.com/en-us/purview/sit-defn-azure-ad-client-secret",
            description=("An application client secret. Microsoft documents only the character set and length; "
                         "the digit + Q~ marker after three characters is the observed shape of current secrets."),
            match_strategy="bounded secret shape",
        ),
        regex_detector(
            "azure-entra-client-secret-labeled-v1", "Microsoft Entra client secret (labelled)", "azure",
            "AZURE_ENTRA_CLIENT_SECRET", ("client_secret", "client-secret", "clientsecret", "client.secret"),
            r"(?i:(?:azure|arm|aad|entra)[_.-]?client[_.-]?secret|azure\.activedirectory\.client-secret)[\"'\s:=]{1,8}"
            r"(?P<secret>[A-Za-z0-9_.~+/=:@?*\[\]-]{32,44})(?:$|[\"'\s,;})&<>])",
            "https://learn.microsoft.com/en-us/purview/sit-defn-azure-ad-client-secret",
            description=("An older client secret without the Q~ marker, recognised only by an Azure client-secret "
                         "config name; a shaped secret is left to the high-confidence detector."),
            match_strategy="labelled value (config key adjacent)",
            confidence="medium",
            validate=lambda secret: not _ENTRA_SHAPED.fullmatch(secret),
        ),
        regex_detector(
            "azure-sas-token-v1", "Azure Storage shared access signature", "azure", "AZURE_SAS_TOKEN",
            ("sig=",),
            r"(?:https?://(?P<account>[a-z0-9]{3,24})\.(?P<service>blob|file|queue|table|dfs)\.core\.windows\.net"
            r"(?:/[^?\s\"'<>#]{0,512})?\?|(?:^|[?;\"'\s=,(]))"
            r"(?P<query>(?:[A-Za-z]{1,8}=[^&\s\"'<>#]*&)*sv=[0-9]{4}-[0-9]{2}-[0-9]{2}"
            r"(?:&[A-Za-z]{1,8}=[^&\s\"'<>#]*)*"
            r"&sig=(?P<secret>(?:[A-Za-z0-9+/]|%2[BbFf]){40,60}(?:=|%3[Dd]){0,2}))(?:$|[&\s\"'<>#;,)])",
            "https://learn.microsoft.com/en-us/azure/storage/common/storage-sas-overview",
            description="A service, account or user delegation SAS: a dated sv= version and an HMAC-SHA256 sig=.",
            match_strategy="signed version and signature in one query",
        ),
        prefix_detector(
            "azure-devops-pat-v1", "Azure DevOps personal access token", "azure_devops", "AZURE_DEVOPS_PAT",
            ("azdo",), r"[A-Za-z0-9]{76}AZDO[A-Za-z0-9]{4}",
            "https://learn.microsoft.com/en-us/purview/sit-defn-azure-devops-personal-access-token",
            description="The 84-character personal access token with the fixed AZDO signature (issued since 2024).",
        ),
        labeled_secret_detector(
            "azure-storage-account-key-v1", "Azure Storage account key", "azure", "AZURE_STORAGE_KEY",
            ("accountkey",), r"AccountKey",
            r"[A-Za-z0-9+/]{86}==",
            "https://learn.microsoft.com/en-us/azure/storage/common/storage-account-keys-manage",
            description="The AccountKey component of an Azure Storage connection string.",
        ),
        labeled_secret_detector(
            "clarifai-pat-v1", "Clarifai personal access token", "clarifai", "CLARIFAI_TOKEN",
            ("clarifai",), r"clarifai[_-]?(?:pat[_-]?|api[_-]?)?(?:key|token)",
            r"[0-9a-f]{32}", "https://docs.clarifai.com/control/authentication/",
        ),
        labeled_secret_detector(
            "bigcommerce-token-v1", "BigCommerce access token", "bigcommerce", "BIGCOMMERCE_TOKEN",
            ("bigcommerce",), r"bigcommerce[_-]?(?:access[_-]?)?token",
            r"[a-z0-9]{31}", "https://developer.bigcommerce.com/docs/start/authentication",
        ),
        labeled_secret_detector(
            "finnhub-api-key-v1", "Finnhub API key", "finnhub", "FINNHUB_API_KEY",
            ("finnhub",), r"finnhub[_-]?(?:api[_-]?)?key",
            r"[a-z0-9]{20}", "https://finnhub.io/docs/api",
        ),
        labeled_secret_detector(
            "twitch-client-secret-v1", "Twitch client secret", "twitch", "TWITCH_CLIENT_SECRET",
            ("twitch",), r"twitch[_-]?client[_-]?secret",
            r"[a-z0-9]{30}", "https://dev.twitch.tv/docs/authentication/",
        ),
        labeled_secret_detector(
            "spotify-client-secret-v1", "Spotify client secret", "spotify", "SPOTIFY_CLIENT_SECRET",
            ("spotify",), r"spotify[_-]?client[_-]?secret",
            r"[a-f0-9]{32}", "https://developer.spotify.com/documentation/web-api/concepts/apps",
        ),

        # ----------------------------------------------------- tenth batch
        prefix_detector(
            "akamai-client-token-v1", "Akamai EdgeGrid client token", "akamai", "AKAMAI_CLIENT_TOKEN",
            ("akab-",), r"akab-[A-Za-z0-9]{16,}-[A-Za-z0-9]{16,}",
            "https://techdocs.akamai.com/developer/docs/set-up-authentication-credentials",
        ),
        prefix_detector(
            "porkbun-key-v1", "Porkbun API key/secret", "porkbun", "PORKBUN_KEY",
            ("pk1_", "sk1_"), r"(?:pk1|sk1)_[a-f0-9]{64}",
            "https://porkbun.com/api/json/v3/documentation",
        ),
        labeled_secret_detector(
            "coda-api-token-v1", "Coda API token", "coda", "CODA_TOKEN",
            ("coda",), r"coda[_-]?(?:api[_-]?)?token",
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            "https://coda.io/developers/apis/v1",
        ),
        labeled_secret_detector(
            "smartsheet-token-v1", "Smartsheet access token", "smartsheet", "SMARTSHEET_TOKEN",
            ("smartsheet",), r"smartsheet[_-]?(?:access[_-]?)?token",
            r"[a-z0-9]{26}", "https://smartsheet.redoc.ly/",
        ),
        labeled_secret_detector(
            "shortcut-token-v1", "Shortcut API token", "shortcut", "SHORTCUT_TOKEN",
            ("shortcut", "clubhouse"), r"(?:shortcut|clubhouse)[_-]?(?:api[_-]?)?token",
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            "https://developer.shortcut.com/api/rest/v3",
        ),
        labeled_secret_detector(
            "todoist-token-v1", "Todoist API token", "todoist", "TODOIST_TOKEN",
            ("todoist",), r"todoist[_-]?(?:api[_-]?)?token",
            r"[0-9a-f]{40}", "https://developer.todoist.com/rest/v2/",
        ),

        # -------------------------------------------------- eleventh batch
        prefix_detector(
            "runpod-api-key-v1", "RunPod API key", "runpod", "RUNPOD_API_KEY",
            ("rpa_",), r"rpa_[A-Z0-9]{40,}",
            "https://docs.runpod.io/get-started/api-keys",
        ),
        prefix_detector(
            "cerebras-api-key-v1", "Cerebras API key", "cerebras", "CEREBRAS_API_KEY",
            ("csk-",), r"csk-[A-Za-z0-9]{40,}",
            "https://inference-docs.cerebras.ai/introduction",
        ),
        labeled_secret_detector(
            "paddle-api-key-v1", "Paddle API key", "paddle", "PADDLE_API_KEY",
            ("paddle",), r"paddle[_-]?(?:api[_-]?)?key",
            r"[a-f0-9]{32,}", "https://developer.paddle.com/api-reference/about/authentication",
        ),
        labeled_secret_detector(
            "ibm-cloud-iam-key-v1", "IBM Cloud IAM API key", "ibm", "IBM_CLOUD_API_KEY",
            ("ibm", "ibmcloud"), r"ibm(?:cloud)?[_-]?(?:api[_-]?)?key",
            r"[A-Za-z0-9_-]{44}", "https://cloud.ibm.com/docs/account?topic=account-userapikey",
        ),
        labeled_secret_detector(
            "webex-token-v1", "Webex access token", "webex", "WEBEX_TOKEN",
            ("webex",), r"webex[_-]?(?:access[_-]?)?token",
            r"[A-Za-z0-9_-]{64}", "https://developer.webex.com/docs/api/getting-started",
        ),
        labeled_secret_detector(
            "box-token-v1", "Box developer token", "box", "BOX_TOKEN",
            ("box",), r"box[_-]?(?:developer[_-]?|access[_-]?)?token",
            r"[A-Za-z0-9]{32}", "https://developer.box.com/guides/authentication/tokens/developer-tokens/",
        ),
        labeled_secret_detector(
            "uploadcare-secret-key-v1", "Uploadcare secret key", "uploadcare", "UPLOADCARE_SECRET_KEY",
            ("uploadcare",), r"uploadcare[_-]?secret[_-]?key",
            r"[a-f0-9]{20}", "https://uploadcare.com/docs/rest-api/requests-auth/",
        ),

        # --------------------------------------------------- twelfth batch
        prefix_detector(
            "onepassword-service-token-v1", "1Password service account token", "1password", "ONEPASSWORD_TOKEN",
            ("ops_",), r"ops_[A-Za-z0-9+/=._-]{100,}",
            "https://developer.1password.com/docs/service-accounts/",
        ),
        labeled_secret_detector(
            "pipedrive-api-token-v1", "Pipedrive API token", "pipedrive", "PIPEDRIVE_TOKEN",
            ("pipedrive",), r"pipedrive[_-]?(?:api[_-]?)?token",
            r"[a-f0-9]{40}", "https://developers.pipedrive.com/docs/api/v1",
        ),
        labeled_secret_detector(
            "webflow-token-v1", "Webflow API token", "webflow", "WEBFLOW_TOKEN",
            ("webflow",), r"webflow[_-]?(?:api[_-]?)?token",
            r"[a-f0-9]{64}", "https://developers.webflow.com/data/reference/authentication",
        ),
        labeled_secret_detector(
            "getresponse-api-key-v1", "GetResponse API key", "getresponse", "GETRESPONSE_API_KEY",
            ("getresponse",), r"getresponse[_-]?(?:api[_-]?)?key",
            r"[a-f0-9]{32}", "https://apidocs.getresponse.com/v3",
        ),
        labeled_secret_detector(
            "ai21-api-key-v1", "AI21 API key", "ai21", "AI21_API_KEY",
            ("ai21",), r"ai21[_-]?(?:api[_-]?)?key",
            r"[A-Za-z0-9]{32}", "https://docs.ai21.com/reference/python-sdk",
        ),
        labeled_secret_detector(
            "wise-api-token-v1", "Wise API token", "wise", "WISE_TOKEN",
            ("wise", "transferwise"), r"(?:wise|transferwise)[_-]?(?:api[_-]?)?token",
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            "https://docs.wise.com/api-docs",
        ),

        # ------------------------------------------- generic credentials
        # Not provider-specific: hardcoded passwords, ID/PW pairs and HTTP Basic
        # auth. These are inherently noisy, so they are LOW confidence, anchored
        # to a label or a structural check, and leaned on the FP policy/entropy.
        generic_assignment_detector(
            "generic-password-assignment-v1", "Hardcoded password", "GENERIC_PASSWORD",
            ("password", "passwd", "pwd"),
            r"(?:password|passwd|pwd)",
            r"[^\"'\r\n]{8,64}",
            # "," and ";" end a bare value (`password=Sup3r, host=db`) rather
            # than becoming part of the credential and its fingerprint.
            r"[^\s'\"`<>(){}\[\]$,;]{8,64}",
            "https://cwe.mitre.org/data/definitions/798.html",
            description="A value assigned to a password/passwd/pwd key.",
        ),
        generic_assignment_detector(
            "generic-secret-assignment-v1", "Hardcoded secret", "GENERIC_SECRET",
            ("secret", "client_secret", "api_secret"),
            r"(?:client[_-]?secret|api[_-]?secret|secret)",
            r"[^\"'\r\n]{16,80}",
            r"[A-Za-z0-9_\-+/=.]{16,80}",
            "https://cwe.mitre.org/data/definitions/798.html",
            description="A value assigned to a secret/client_secret/api_secret key.",
        ),
        regex_detector(
            "basic-auth-url-v1", "Basic-auth credentials in URL", "generic", "BASIC_AUTH_URL",
            ("://",),
            r"(?P<secret>(?:https?|ftps?|ssh|smtps?|imaps?|amqps?|ldaps?)://"
            r"[^/\s:@]+:[^/\s:@]{3,}@[A-Za-z0-9._-]+)",
            "https://www.rfc-editor.org/rfc/rfc3986#section-3.2.1",
            description="A URL embedding userinfo (user:password@host) for a non-database scheme.",
            match_strategy="userinfo component",
            confidence="medium",
            span=512,
        ),
        regex_detector(
            "http-basic-auth-header-v1", "HTTP Basic authorization header", "generic", "HTTP_BASIC_AUTH",
            ("basic ", "authorization"),
            r"(?i:authorization)\s*[:=]\s*(?i:basic)\s+(?P<secret>[A-Za-z0-9+/]{16,}={0,2})",
            "https://www.rfc-editor.org/rfc/rfc7617",
            description="An HTTP Basic Authorization header whose base64 decodes to user:password.",
            match_strategy="RFC 7617 base64(user:pass)",
            confidence="medium",
            validate=basic_auth_b64,
        ),
        labeled_secret_detector(
            "generic-api-key-assignment-v1", "Hardcoded API key", "generic", "GENERIC_API_KEY",
            ("api_key", "apikey", "access_token", "api-key", "refresh_token", "refresh-token",
             "bot_token", "user_token", "app_token"),
            # A refresh token is not a lesser secret than the access token it
            # mints, and a bot/user/app token is often written to configuration
            # under its role name rather than as "access_token".
            r"(?:api[_-]?key|apikey|(?:access|refresh)[_-]?token"
            r"|(?:app|bot|user)[_-]?token)",
            r"[A-Za-z0-9_\-.]{16,80}",
            "https://cwe.mitre.org/data/definitions/798.html",
            description="A value assigned to an api_key, access_token, refresh_token or an "
                        "app/bot/user token key.",
            confidence="low",
            validate=min_entropy(3.0),
        ),
        regex_detector(
            "http-bearer-token-v1", "HTTP Bearer authorization token", "generic",
            "HTTP_BEARER_TOKEN",
            ("bearer ",),
            r"(?i:bearer)[ 	]+(?P<secret>[A-Za-z0-9._~+/-]{20,400}=*)",
            "https://www.rfc-editor.org/rfc/rfc6750#section-2.1",
            description="An opaque bearer credential in an Authorization header or a "
                        "recorded request. The scheme says it is a credential; it does "
                        "not say which provider issued it.",
            match_strategy="RFC 6750 bearer scheme",
            confidence="low",
            span=512,
            validate=min_entropy(3.0),
        ),
        regex_detector(
            "bcrypt-hash-v1", "bcrypt password hash", "generic", "PASSWORD_HASH",
            ("$2a$", "$2b$", "$2y$"),
            r"(?P<secret>\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53})",
            "https://en.wikipedia.org/wiki/Bcrypt#Description",
            description="A bcrypt password hash (sensitive; enables offline cracking).",
            match_strategy="bcrypt modular-crypt format",
            confidence="medium",
        ),
        labeled_secret_detector(
            "rails-secret-key-base-v1", "Rails secret_key_base", "rails", "RAILS_SECRET_KEY_BASE",
            ("secret_key_base",), r"secret_key_base",
            r"[a-f0-9]{128}",
            "https://guides.rubyonrails.org/security.html#custom-credentials",
            description="The Rails secret_key_base (signs sessions/cookies).",
        ),

        # ------------------------------------------- thirteenth batch (providers)
        prefix_detector(
            "age-secret-key-v1", "age secret key", "age", "AGE_SECRET_KEY",
            ("age-secret-key-1",), r"AGE-SECRET-KEY-1[0-9A-Z]{58}",
            "https://github.com/FiloSottile/age",
            description="An age file-encryption secret key (bech32).",
        ),
        prefix_detector(
            "toss-payments-secret-key-v1", "Toss Payments secret key", "toss", "TOSS_SECRET_KEY",
            ("test_sk_", "live_sk_"), r"(?:test|live)_sk_[A-Za-z0-9]{24,}",
            "https://docs.tosspayments.com/reference/using-api/api-keys",
            confidence="medium",
        ),
        prefix_detector(
            "coingecko-api-key-v1", "CoinGecko API key", "coingecko", "COINGECKO_API_KEY",
            ("cg-",), r"CG-[A-Za-z0-9]{20,}",
            "https://docs.coingecko.com/reference/authentication",
        ),
        regex_detector(
            "apache-md5-hash-v1", "Apache apr1 password hash", "generic", "PASSWORD_HASH",
            ("$apr1$",), r"(?P<secret>\$apr1\$[./A-Za-z0-9]{8}\$[./A-Za-z0-9]{22})",
            "https://httpd.apache.org/docs/current/misc/password_encryptions.html",
            description="An Apache apr1 (htpasswd) password hash.",
            confidence="medium",
        ),

        # --------------------------------------- fourteenth batch (providers)
        prefix_detector(
            "intercom-access-token-v1", "Intercom access token", "intercom", "INTERCOM_TOKEN",
            ("dg9r",), r"dG9r[A-Za-z0-9+/=_-]{36,}",
            "https://developers.intercom.com/docs/build-an-integration/learn-more/authentication/",
            description="An Intercom access token (base64 beginning 'dG9r').",
            confidence="medium",
        ),
        prefix_detector(
            "courier-auth-token-v1", "Courier auth token", "courier", "COURIER_TOKEN",
            ("pk_prod_", "pk_test_", "dk_prod_", "dk_test_"),
            r"(?:pk|dk)_(?:prod|test)_[A-Za-z0-9]{32,}",
            "https://www.courier.com/docs/reference/authentication/",
            confidence="medium",
        ),
        prefix_detector(
            "onesignal-rest-key-v1", "OneSignal REST API key", "onesignal", "ONESIGNAL_REST_KEY",
            ("os_v2_",), r"os_v2_app_[a-z0-9_-]{40,}",
            "https://documentation.onesignal.com/docs/keys-and-ids",
            confidence="medium",
        ),
        prefix_detector(
            "deepseek-api-key-v1", "DeepSeek API key", "deepseek", "DEEPSEEK_API_KEY",
            ("sk-",), r"sk-[0-9a-f]{32}",
            "https://api-docs.deepseek.com/",
            description="A DeepSeek API key (sk- + 32 hex).",
            confidence="medium",
        ),
        labeled_secret_detector(
            "kakao-rest-key-v1", "Kakao REST API key", "kakao", "KAKAO_REST_KEY",
            ("kakao",), r"kakao[_-]?(?:rest[_-]?)?(?:api[_-]?)?key",
            r"[0-9a-f]{32}", "https://developers.kakao.com/docs/latest/en/getting-started/app",
        ),
        regex_detector(
            "unix-crypt-hash-v1", "Unix crypt password hash", "generic", "PASSWORD_HASH",
            ("$1$", "$5$", "$6$"),
            r"(?P<secret>\$[156]\$(?:rounds=[0-9]+\$)?[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{22,86})",
            "https://man7.org/linux/man-pages/man3/crypt.3.html",
            description="A Unix md5crypt/sha256crypt/sha512crypt password hash.",
            confidence="medium",
        ),
        regex_detector(
            "django-pbkdf2-hash-v1", "Django PBKDF2 password hash", "generic", "PASSWORD_HASH",
            ("pbkdf2_sha256$",),
            r"(?P<secret>pbkdf2_sha256\$[0-9]+\$[A-Za-z0-9+/._=-]{1,64}\$[A-Za-z0-9+/=]{20,})",
            "https://docs.djangoproject.com/en/stable/topics/auth/passwords/",
            description="A Django PBKDF2-SHA256 password hash.",
            confidence="medium",
        ),

        # ---------------------------------------- fifteenth batch (providers)
        prefix_detector(
            "wakatime-api-key-v1", "WakaTime API key", "wakatime", "WAKATIME_API_KEY",
            ("waka_",),
            r"waka_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            "https://wakatime.com/developers",
        ),
        labeled_secret_detector(
            "lob-api-key-v1", "Lob API key", "lob", "LOB_API_KEY",
            ("lob",), r"lob[_-]?(?:api[_-]?)?key",
            r"(?:live|test)_[a-f0-9]{35}", "https://docs.lob.com/#tag/Authentication",
        ),
        labeled_secret_detector(
            "bunny-api-key-v1", "Bunny.net API key", "bunny", "BUNNY_API_KEY",
            ("bunny", "bunnynet"), r"bunny(?:net)?[_-]?(?:api[_-]?)?key",
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            "https://docs.bunny.net/reference/bunnynet-api-overview",
        ),
        labeled_secret_detector(
            "facebook-app-secret-v1", "Facebook app secret", "facebook", "FACEBOOK_APP_SECRET",
            ("facebook", "fb_app"), r"(?:facebook|fb)[_-]?app[_-]?secret",
            r"[a-f0-9]{32}", "https://developers.facebook.com/docs/facebook-login/guides/access-tokens/",
        ),
        labeled_secret_detector(
            "twitter-api-secret-v1", "Twitter/X API secret", "twitter", "TWITTER_API_SECRET",
            ("twitter", "consumer_secret"), r"(?:twitter|consumer)[_-]?(?:api[_-]?)?secret",
            r"[A-Za-z0-9]{50}", "https://developer.x.com/en/docs/authentication/oauth-1-0a",
        ),

        # ---------------------------------------- sixteenth batch (providers)
        # (OpenAI sk-proj, Clerk sk_live_ and Fly.io fo1_ intentionally omitted:
        #  their formats overlap existing detectors and would double-report.)
        prefix_detector(
            "gitlab-feed-token-v1", "GitLab feed token", "gitlab", "GITLAB_FEED_TOKEN",
            ("glft-",), r"glft-[A-Za-z0-9_-]{20}",
            "https://docs.gitlab.com/ee/security/token_overview.html",
        ),
        prefix_detector(
            "gitlab-oauth-app-secret-v1", "GitLab OAuth application secret", "gitlab", "GITLAB_OAUTH_SECRET",
            ("gloas-",), r"gloas-[A-Za-z0-9_-]{64}",
            "https://docs.gitlab.com/ee/security/token_overview.html",
        ),
        prefix_detector(
            "sentry-org-token-v1", "Sentry org auth token", "sentry", "SENTRY_ORG_TOKEN",
            ("sntryu_",), r"sntryu_[A-Za-z0-9]{64}",
            "https://docs.sentry.io/account/auth-tokens/",
        ),
        prefix_detector(
            "scaleway-api-key-id-v1", "Scaleway API key ID (SCW)", "scaleway", "SCALEWAY_ACCESS_KEY",
            ("scw",), r"SCW[A-Z0-9]{17}",
            "https://www.scaleway.com/en/docs/identity-and-access-management/iam/how-to/create-api-keys/",
            description="A Scaleway access key identifier (pairs with a secret key).",
        ),
        prefix_detector(
            "yandex-oauth-token-v1", "Yandex OAuth token", "yandex", "YANDEX_OAUTH_TOKEN",
            ("y0_",), r"y0_[A-Za-z0-9_-]{40,}",
            "https://yandex.cloud/en/docs/iam/concepts/authorization/oauth-token",
            confidence="medium",
        ),
        labeled_secret_detector(
            "vercel-token-v1", "Vercel access token", "vercel", "VERCEL_TOKEN",
            ("vercel",), r"vercel[_-]?(?:api[_-]?)?token",
            r"[A-Za-z0-9]{24}", "https://vercel.com/docs/rest-api#authentication",
        ),
        labeled_secret_detector(
            "statuspage-api-key-v1", "Statuspage API key", "statuspage", "STATUSPAGE_API_KEY",
            ("statuspage",), r"statuspage[_-]?(?:api[_-]?)?key",
            r"[0-9a-f]{32}", "https://developer.statuspage.io/",
        ),

        # ------------------------------------ seventeenth batch (providers)
        prefix_detector(
            "anyscale-api-key-v1", "Anyscale API key", "anyscale", "ANYSCALE_API_KEY",
            ("esecret_",), r"esecret_[A-Za-z0-9]{24,}",
            "https://docs.anyscale.com/",
            confidence="medium",
        ),
        labeled_secret_detector(
            "railway-token-v1", "Railway token", "railway", "RAILWAY_TOKEN",
            ("railway",), r"railway[_-]?(?:api[_-]?|project[_-]?)?token",
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            "https://docs.railway.com/reference/public-api",
        ),
        labeled_secret_detector(
            "auth0-client-secret-v1", "Auth0 client secret", "auth0", "AUTH0_CLIENT_SECRET",
            ("auth0",), r"auth0[_-]?(?:client[_-]?)?secret",
            r"[A-Za-z0-9_-]{40,}", "https://auth0.com/docs/secure/application-credentials",
        ),
        labeled_secret_detector(
            "zendesk-api-token-v1", "Zendesk API token", "zendesk", "ZENDESK_TOKEN",
            ("zendesk",), r"zendesk[_-]?(?:api[_-]?)?token",
            r"[A-Za-z0-9]{40}", "https://developer.zendesk.com/api-reference/introduction/security-and-auth/",
        ),

        # -------------------------------- eighteenth batch (labelled, low FP)
        labeled_secret_detector(
            "stability-api-key-v1", "Stability AI API key", "stability", "STABILITY_API_KEY",
            ("stability",), r"stability[_-]?(?:ai[_-]?)?(?:api[_-]?)?key",
            r"sk-[A-Za-z0-9]{48}", "https://platform.stability.ai/docs/getting-started/authentication",
        ),
        labeled_secret_detector(
            "voyage-api-key-v1", "Voyage AI API key", "voyage", "VOYAGE_API_KEY",
            ("voyage",), r"voyage[_-]?(?:ai[_-]?)?(?:api[_-]?)?key",
            r"pa-[A-Za-z0-9_-]{36,}", "https://docs.voyageai.com/docs/api-key-and-installation",
        ),
        labeled_secret_detector(
            "messagebird-api-key-v1", "MessageBird API key", "messagebird", "MESSAGEBIRD_API_KEY",
            ("messagebird",), r"messagebird[_-]?(?:api[_-]?)?key",
            r"[A-Za-z0-9]{25}", "https://developers.messagebird.com/api/#authentication",
            confidence="low",
        ),
        labeled_secret_detector(
            "nexmo-api-secret-v1", "Vonage/Nexmo API secret", "vonage", "VONAGE_API_SECRET",
            ("nexmo", "vonage"), r"(?:nexmo|vonage)[_-]?(?:api[_-]?)?secret",
            r"[A-Za-z0-9]{16}", "https://developer.vonage.com/en/getting-started/concepts/authentication",
            confidence="low",
        ),
        labeled_secret_detector(
            "recurly-api-key-v1", "Recurly API key", "recurly", "RECURLY_API_KEY",
            ("recurly",), r"recurly[_-]?(?:api[_-]?)?key",
            r"[0-9a-f]{32}", "https://recurly.com/developers/api/",
            confidence="low",
        ),
        labeled_secret_detector(
            "elastic-api-key-v1", "Elastic API key", "elastic", "ELASTIC_API_KEY",
            ("elastic",), r"elastic[_-]?(?:search[_-]?)?(?:api[_-]?)?key",
            r"[A-Za-z0-9+/=_-]{40,}", "https://www.elastic.co/guide/en/elasticsearch/reference/current/security-api-create-api-key.html",
            confidence="low",
        ),

        # ---- nineteenth batch: well-known providers, label-gated, low conf ----
        # A documented provider config key must sit next to a token-shaped value;
        # confidence is low so these never outrank self-identifying matches.
        *_labelled_batch([
            ("baseten-api-key-v1", "Baseten API key", "baseten", "BASETEN_API_KEY",
             r"baseten[_-]?(?:api[_-]?)?key", "https://docs.baseten.co/observability/api-keys"),
            ("writer-api-key-v1", "Writer API key", "writer", "WRITER_API_KEY",
             r"writer[_-]?(?:api[_-]?)?key", "https://dev.writer.com/api-guides/quickstart"),
            ("nomic-api-key-v1", "Nomic API key", "nomic", "NOMIC_API_KEY",
             r"nomic[_-]?(?:api[_-]?)?key", "https://docs.nomic.ai/"),
            ("deepinfra-api-key-v1", "DeepInfra API key", "deepinfra", "DEEPINFRA_API_KEY",
             r"deepinfra[_-]?(?:api[_-]?)?key", "https://deepinfra.com/docs"),
            ("octoai-api-key-v1", "OctoAI API token", "octoai", "OCTOAI_API_KEY",
             r"octoai[_-]?(?:api[_-]?)?(?:key|token)", "https://octo.ai/docs/getting-started/how-to-create-an-octoai-access-token"),
            ("fivetran-api-key-v1", "Fivetran API key", "fivetran", "FIVETRAN_API_KEY",
             r"fivetran[_-]?(?:api[_-]?)?key", "https://fivetran.com/docs/rest-api/getting-started"),
            ("hightouch-api-key-v1", "Hightouch API key", "hightouch", "HIGHTOUCH_API_KEY",
             r"hightouch[_-]?(?:api[_-]?)?key", "https://hightouch.com/docs/api-reference/introduction"),
            ("census-api-key-v1", "Census API key", "census", "CENSUS_API_KEY",
             r"census[_-]?(?:api[_-]?)?key", "https://developers.getcensus.com/api-reference/introduction"),
            ("upstash-token-v1", "Upstash REST token", "upstash", "UPSTASH_TOKEN",
             r"upstash[_-]?(?:rest[_-]?)?(?:token|key)", "https://upstash.com/docs/redis/features/restapi"),
            ("logzio-api-token-v1", "Logz.io API token", "logzio", "LOGZIO_TOKEN",
             r"logz[_-]?io[_-]?(?:api[_-]?)?token", "https://api-docs.logz.io/docs/logz/logz-io-api/"),
            ("betterstack-token-v1", "Better Stack API token", "betterstack", "BETTERSTACK_TOKEN",
             r"better[_-]?stack[_-]?(?:api[_-]?)?token", "https://betterstack.com/docs/uptime/api/"),
            ("raygun-api-key-v1", "Raygun API key", "raygun", "RAYGUN_API_KEY",
             r"raygun[_-]?(?:api[_-]?)?key", "https://raygun.com/documentation/product-guides/api-keys/"),
            ("honeybadger-api-key-v1", "Honeybadger API key", "honeybadger", "HONEYBADGER_API_KEY",
             r"honeybadger[_-]?(?:api[_-]?)?key", "https://docs.honeybadger.io/api/reporting/"),
            ("appdynamics-key-v1", "AppDynamics API key", "appdynamics", "APPDYNAMICS_KEY",
             r"appdynamics[_-]?(?:api[_-]?)?key", "https://docs.appdynamics.com/appd/onprem/en/extend-cisco-appdynamics/cisco-appdynamics-apis"),
            ("chargebee-api-key-v1", "Chargebee API key", "chargebee", "CHARGEBEE_API_KEY",
             r"chargebee[_-]?(?:api[_-]?)?key", "https://apidocs.chargebee.com/docs/api/auth"),
            ("authorizenet-key-v1", "Authorize.Net transaction key", "authorizenet", "AUTHORIZENET_KEY",
             r"authorize[_-]?net[_-]?(?:transaction[_-]?|api[_-]?)?key", "https://developer.authorize.net/api/reference/features/credentials.html"),
            ("sinch-api-token-v1", "Sinch API token", "sinch", "SINCH_TOKEN",
             r"sinch[_-]?(?:api[_-]?)?(?:token|key)", "https://developers.sinch.com/docs/sms/api-reference/"),
            ("infobip-api-key-v1", "Infobip API key", "infobip", "INFOBIP_API_KEY",
             r"infobip[_-]?(?:api[_-]?)?key", "https://www.infobip.com/docs/api"),
            ("activecampaign-api-key-v1", "ActiveCampaign API key", "activecampaign", "ACTIVECAMPAIGN_KEY",
             r"active[_-]?campaign[_-]?(?:api[_-]?)?key", "https://developers.activecampaign.com/reference/authentication"),
            ("customerio-api-key-v1", "Customer.io API key", "customerio", "CUSTOMERIO_KEY",
             r"customer[_-]?io[_-]?(?:app[_-]?|api[_-]?)?key", "https://docs.customer.io/integrations/api/"),
            ("iterable-api-key-v1", "Iterable API key", "iterable", "ITERABLE_API_KEY",
             r"iterable[_-]?(?:api[_-]?)?key", "https://api.iterable.com/api/docs"),
            ("braze-api-key-v1", "Braze API key", "braze", "BRAZE_API_KEY",
             r"braze[_-]?(?:api[_-]?)?key", "https://www.braze.com/docs/api/basics/"),
            ("mailerlite-api-key-v1", "MailerLite API key", "mailerlite", "MAILERLITE_KEY",
             r"mailerlite[_-]?(?:api[_-]?)?key", "https://developers.mailerlite.com/docs/"),
        ]),

        # ---- twentieth batch: more well-known providers, label-gated, low conf ----
        *_labelled_batch([
            ("dbt-cloud-token-v1", "dbt Cloud API token", "dbt", "DBT_CLOUD_TOKEN",
             r"dbt[_-]?(?:cloud[_-]?)?(?:api[_-]?)?token", "https://docs.getdbt.com/docs/dbt-cloud-apis/authentication"),
            ("airbyte-api-key-v1", "Airbyte API key", "airbyte", "AIRBYTE_API_KEY",
             r"airbyte[_-]?(?:api[_-]?)?(?:key|token)", "https://reference.airbyte.com/reference/authentication"),
            ("dagster-cloud-token-v1", "Dagster Cloud token", "dagster", "DAGSTER_TOKEN",
             r"dagster[_-]?(?:cloud[_-]?)?(?:api[_-]?)?token", "https://docs.dagster.io/dagster-plus/deployment/management/tokens"),
            ("qdrant-api-key-v1", "Qdrant API key", "qdrant", "QDRANT_API_KEY",
             r"qdrant[_-]?(?:api[_-]?)?key", "https://qdrant.tech/documentation/cloud/authentication/"),
            ("weaviate-api-key-v1", "Weaviate API key", "weaviate", "WEAVIATE_API_KEY",
             r"weaviate[_-]?(?:api[_-]?)?key", "https://weaviate.io/developers/weaviate/configuration/authentication"),
            ("influxdb-token-v1", "InfluxDB token", "influxdb", "INFLUXDB_TOKEN",
             r"influxdb[_-]?token", "https://docs.influxdata.com/influxdb/v2/admin/tokens/"),
            ("neo4j-auth-v1", "Neo4j auth credential", "neo4j", "NEO4J_AUTH",
             r"neo4j[_-]?(?:password|auth|token)", "https://neo4j.com/docs/operations-manual/current/authentication-authorization/"),
            ("coralogix-api-key-v1", "Coralogix API key", "coralogix", "CORALOGIX_KEY",
             r"coralogix[_-]?(?:api[_-]?)?key", "https://coralogix.com/docs/api-keys/"),
            ("mezmo-api-key-v1", "Mezmo (LogDNA) API key", "mezmo", "MEZMO_KEY",
             r"mezmo[_-]?(?:api[_-]?)?key", "https://docs.mezmo.com/docs/ingestion-key"),
            ("instana-api-token-v1", "Instana API token", "instana", "INSTANA_TOKEN",
             r"instana[_-]?(?:api[_-]?)?token", "https://www.ibm.com/docs/en/instana-observability/current?topic=apis-web-rest-api"),
            ("logrocket-api-key-v1", "LogRocket API key", "logrocket", "LOGROCKET_KEY",
             r"logrocket[_-]?(?:api[_-]?)?key", "https://docs.logrocket.com/reference/authentication"),
            ("fullstory-api-key-v1", "FullStory API key", "fullstory", "FULLSTORY_KEY",
             r"fullstory[_-]?(?:api[_-]?)?key", "https://developer.fullstory.com/server/v2/authentication/"),
            ("adyen-api-key-v1", "Adyen API key", "adyen", "ADYEN_API_KEY",
             r"adyen[_-]?(?:api[_-]?)?key", "https://docs.adyen.com/development-resources/api-credentials/"),
            ("checkout-secret-key-v1", "Checkout.com secret key", "checkout", "CHECKOUT_SECRET_KEY",
             r"checkout[_-]?(?:com[_-]?)?(?:secret[_-]?key|api[_-]?key)", "https://www.checkout.com/docs/developer-resources/api-authentication"),
            ("dwolla-api-secret-v1", "Dwolla API secret", "dwolla", "DWOLLA_SECRET",
             r"dwolla[_-]?(?:api[_-]?)?secret", "https://developers.dwolla.com/api-reference/authorization"),
            ("rapyd-access-key-v1", "Rapyd access key", "rapyd", "RAPYD_ACCESS_KEY",
             r"rapyd[_-]?(?:access[_-]?|api[_-]?)?key", "https://docs.rapyd.net/en/api-authentication.html"),
            ("brex-api-token-v1", "Brex API token", "brex", "BREX_TOKEN",
             r"brex[_-]?(?:api[_-]?)?token", "https://developer.brex.com/docs/authentication/"),
            ("telnyx-api-key-v1", "Telnyx API key", "telnyx", "TELNYX_API_KEY",
             r"telnyx[_-]?(?:api[_-]?)?key", "https://developers.telnyx.com/docs/api/v2/overview"),
            ("bandwidth-token-v1", "Bandwidth API token", "bandwidth", "BANDWIDTH_TOKEN",
             r"bandwidth[_-]?(?:api[_-]?)?token", "https://dev.bandwidth.com/docs/"),
            ("ovh-application-secret-v1", "OVH application secret", "ovh", "OVH_APP_SECRET",
             r"ovh[_-]?(?:application[_-]?)?(?:secret|key)", "https://help.ovhcloud.com/csm/en-api-getting-started-ovhcloud-api"),
            ("gandi-api-key-v1", "Gandi API key", "gandi", "GANDI_API_KEY",
             r"gandi[_-]?(?:api[_-]?)?key", "https://api.gandi.net/docs/authentication/"),
            ("namecheap-api-key-v1", "Namecheap API key", "namecheap", "NAMECHEAP_KEY",
             r"namecheap[_-]?(?:api[_-]?)?key", "https://www.namecheap.com/support/api/intro/"),
            ("harness-api-key-v1", "Harness API key", "harness", "HARNESS_API_KEY",
             r"harness[_-]?(?:api[_-]?)?(?:key|token)", "https://developer.harness.io/docs/platform/automation/api/add-and-manage-api-keys/"),
            ("spacelift-api-token-v1", "Spacelift API token", "spacelift", "SPACELIFT_TOKEN",
             r"spacelift[_-]?(?:api[_-]?)?token", "https://docs.spacelift.io/integrations/api"),
            ("jenkins-api-token-v1", "Jenkins API token", "jenkins", "JENKINS_TOKEN",
             r"jenkins[_-]?(?:api[_-]?)?token", "https://www.jenkins.io/doc/book/using/remote-access-api/"),
            ("travis-ci-token-v1", "Travis CI token", "travis", "TRAVIS_TOKEN",
             r"travis[_-]?(?:ci[_-]?)?token", "https://docs.travis-ci.com/api/"),
            ("zoho-oauth-token-v1", "Zoho OAuth token", "zoho", "ZOHO_TOKEN",
             r"zoho[_-]?(?:oauth[_-]?)?token", "https://www.zoho.com/crm/developer/docs/api/v3/auth-request.html"),
            ("convertkit-api-secret-v1", "ConvertKit API secret", "convertkit", "CONVERTKIT_SECRET",
             r"convertkit[_-]?(?:api[_-]?)?(?:secret|key)", "https://developers.convertkit.com/"),
            ("omnisend-api-key-v1", "Omnisend API key", "omnisend", "OMNISEND_KEY",
             r"omnisend[_-]?(?:api[_-]?)?key", "https://api-docs.omnisend.com/reference/intro"),
            ("beehiiv-api-key-v1", "beehiiv API key", "beehiiv", "BEEHIIV_KEY",
             r"beehiiv[_-]?(?:api[_-]?)?key", "https://developers.beehiiv.com/docs/v2"),
            ("freshdesk-api-key-v1", "Freshdesk API key", "freshdesk", "FRESHDESK_KEY",
             r"freshdesk[_-]?(?:api[_-]?)?key", "https://developers.freshdesk.com/api/#authentication"),
            ("salesforce-token-v1", "Salesforce access token", "salesforce", "SALESFORCE_TOKEN",
             r"salesforce[_-]?(?:access[_-]?)?token", "https://help.salesforce.com/s/articleView?id=sf.remoteaccess_oauth_tokens.htm"),
        ]),

        # ---- twenty-first batch: security / comms / payment / marketing ----
        *_labelled_batch([
            ("gitguardian-api-key-v1", "GitGuardian API key", "gitguardian", "GITGUARDIAN_KEY",
             r"gitguardian[_-]?(?:api[_-]?)?(?:key|token)", "https://docs.gitguardian.com/api-docs/authentication"),
            ("semgrep-app-token-v1", "Semgrep app token", "semgrep", "SEMGREP_TOKEN",
             r"semgrep[_-]?(?:app[_-]?)?token", "https://semgrep.dev/docs/semgrep-appsec-platform/tokens"),
            ("wiz-api-secret-v1", "Wiz API client secret", "wiz", "WIZ_SECRET",
             r"wiz[_-]?(?:api[_-]?)?(?:client[_-]?)?secret", "https://docs.wiz.io/wiz-docs/docs/using-the-api"),
            ("tenable-access-key-v1", "Tenable access key", "tenable", "TENABLE_KEY",
             r"tenable[_-]?(?:access[_-]?|secret[_-]?|api[_-]?)?key", "https://developer.tenable.com/docs/authorization"),
            ("veracode-api-key-v1", "Veracode API key", "veracode", "VERACODE_KEY",
             r"veracode[_-]?(?:api[_-]?)?key", "https://docs.veracode.com/r/c_api_credentials3"),
            ("lacework-api-secret-v1", "Lacework API secret", "lacework", "LACEWORK_SECRET",
             r"lacework[_-]?(?:api[_-]?)?secret", "https://docs.lacework.net/api/api-access-keys-and-tokens"),
            ("agora-app-certificate-v1", "Agora app certificate", "agora", "AGORA_CERTIFICATE",
             r"agora[_-]?(?:app[_-]?)?certificate", "https://docs.agora.io/en/video-calling/get-started/manage-agora-account"),
            ("livekit-api-secret-v1", "LiveKit API secret", "livekit", "LIVEKIT_SECRET",
             r"livekit[_-]?(?:api[_-]?)?secret", "https://docs.livekit.io/home/get-started/api-keys/"),
            ("getstream-api-secret-v1", "Stream (getstream) API secret", "getstream", "GETSTREAM_SECRET",
             r"getstream[_-]?(?:api[_-]?)?secret", "https://getstream.io/chat/docs/"),
            ("sendbird-api-token-v1", "Sendbird API token", "sendbird", "SENDBIRD_TOKEN",
             r"sendbird[_-]?(?:api[_-]?)?token", "https://sendbird.com/docs/chat/platform-api/v3/prepare-to-use-api"),
            ("ably-api-key-v1", "Ably API key", "ably", "ABLY_API_KEY",
             r"ably[_-]?(?:api[_-]?)?key", "https://ably.com/docs/auth/basic"),
            ("lemonsqueezy-api-key-v1", "Lemon Squeezy API key", "lemonsqueezy", "LEMONSQUEEZY_KEY",
             r"lemon[_-]?squeezy[_-]?(?:api[_-]?)?key", "https://docs.lemonsqueezy.com/api"),
            ("paystack-secret-key-v1", "Paystack secret key", "paystack", "PAYSTACK_SECRET_KEY",
             r"paystack[_-]?(?:secret[_-]?)?key", "https://paystack.com/docs/api/"),
            ("mercury-api-token-v1", "Mercury API token", "mercury", "MERCURY_TOKEN",
             r"mercury[_-]?(?:api[_-]?)?token", "https://docs.mercury.com/reference/welcome-to-mercury-api"),
            ("revolut-api-key-v1", "Revolut API key", "revolut", "REVOLUT_KEY",
             r"revolut[_-]?(?:api[_-]?)?(?:key|secret)", "https://developer.revolut.com/docs/business/business-api"),
            ("ramp-client-secret-v1", "Ramp API client secret", "ramp", "RAMP_SECRET",
             r"ramp[_-]?(?:api[_-]?)?(?:client[_-]?)?secret", "https://docs.ramp.com/developer-api/v1/authorization"),
            ("moderntreasury-api-key-v1", "Modern Treasury API key", "moderntreasury", "MODERNTREASURY_KEY",
             r"modern[_-]?treasury[_-]?(?:api[_-]?)?key", "https://docs.moderntreasury.com/reference/authentication"),
            ("marqeta-api-key-v1", "Marqeta API key", "marqeta", "MARQETA_KEY",
             r"marqeta[_-]?(?:api[_-]?)?(?:key|token)", "https://www.marqeta.com/docs/core-api/authentication"),
            ("segment-write-key-v1", "Segment write key", "segment", "SEGMENT_WRITE_KEY",
             r"segment[_-]?(?:write[_-]?)?key", "https://segment.com/docs/connections/find-writekey/"),
            ("rudderstack-write-key-v1", "RudderStack write key", "rudderstack", "RUDDERSTACK_KEY",
             r"rudderstack[_-]?(?:write[_-]?)?key", "https://www.rudderstack.com/docs/"),
            ("plausible-api-key-v1", "Plausible API key", "plausible", "PLAUSIBLE_KEY",
             r"plausible[_-]?(?:api[_-]?)?key", "https://plausible.io/docs/stats-api"),
            ("fathom-api-token-v1", "Fathom Analytics API token", "fathom", "FATHOM_TOKEN",
             r"fathom[_-]?(?:api[_-]?)?(?:token|key)", "https://usefathom.com/api"),
            ("matomo-api-token-v1", "Matomo API token", "matomo", "MATOMO_TOKEN",
             r"matomo[_-]?(?:api[_-]?)?(?:token|auth)", "https://developer.matomo.org/api-reference/reporting-api"),
            ("pendo-integration-key-v1", "Pendo integration key", "pendo", "PENDO_KEY",
             r"pendo[_-]?(?:integration[_-]?)?key", "https://engageapi.pendo.io/"),
            ("imgix-api-key-v1", "imgix API key", "imgix", "IMGIX_KEY",
             r"imgix[_-]?(?:api[_-]?)?key", "https://docs.imgix.com/setup/api"),
            ("mux-token-secret-v1", "Mux token secret", "mux", "MUX_TOKEN_SECRET",
             r"mux[_-]?(?:token[_-]?)?secret", "https://docs.mux.com/core/make-api-requests"),
            ("transloadit-auth-secret-v1", "Transloadit auth secret", "transloadit", "TRANSLOADIT_SECRET",
             r"transloadit[_-]?(?:auth[_-]?)?secret", "https://transloadit.com/docs/topics/authentication/"),
            ("cloudsmith-api-key-v1", "Cloudsmith API key", "cloudsmith", "CLOUDSMITH_KEY",
             r"cloudsmith[_-]?(?:api[_-]?)?key", "https://help.cloudsmith.io/docs/api"),
            ("drift-api-token-v1", "Drift API token", "drift", "DRIFT_TOKEN",
             r"drift[_-]?(?:api[_-]?)?token", "https://devdocs.drift.com/docs/authentication"),
            ("helpscout-app-secret-v1", "Help Scout app secret", "helpscout", "HELPSCOUT_SECRET",
             r"help[_-]?scout[_-]?(?:app[_-]?)?secret", "https://developer.helpscout.com/mailbox-api/overview/authentication/"),
            ("gorgias-api-key-v1", "Gorgias API key", "gorgias", "GORGIAS_KEY",
             r"gorgias[_-]?(?:api[_-]?)?key", "https://developers.gorgias.com/reference/authentication"),
            ("loops-api-key-v1", "Loops API key", "loops", "LOOPS_KEY",
             r"loops[_-]?(?:api[_-]?)?key", "https://loops.so/docs/api-reference/intro"),
            ("salesloft-api-key-v1", "Salesloft API key", "salesloft", "SALESLOFT_KEY",
             r"salesloft[_-]?(?:api[_-]?)?key", "https://developers.salesloft.com/docs/platform/api-basics/authentication/"),
            ("apollo-api-key-v1", "Apollo.io API key", "apollo", "APOLLO_KEY",
             r"apollo[_-]?(?:io[_-]?)?(?:api[_-]?)?key", "https://docs.apollo.io/reference/authentication"),
            ("gong-api-secret-v1", "Gong API secret", "gong", "GONG_SECRET",
             r"gong[_-]?(?:api[_-]?)?(?:key|secret)", "https://gong.app.gong.io/settings/api/documentation"),
            ("sonatype-token-v1", "Sonatype Nexus token", "sonatype", "SONATYPE_TOKEN",
             r"sonatype[_-]?(?:api[_-]?)?token", "https://help.sonatype.com/en/rest-api.html"),
        ]),

        # ---- twenty-second batch: AI / DB / CMS / commerce / monitoring / cloud ----
        *_labelled_batch([
            # AI / ML
            ("novita-api-key-v1", "Novita AI API key", "novita", "NOVITA_API_KEY",
             r"novita[_-]?(?:api[_-]?)?key", "https://novita.ai/docs/get-started/quickstart.html"),
            ("sambanova-api-key-v1", "SambaNova API key", "sambanova", "SAMBANOVA_API_KEY",
             r"sambanova[_-]?(?:api[_-]?)?key", "https://docs.sambanova.ai/"),
            ("lepton-api-token-v1", "Lepton AI token", "lepton", "LEPTON_TOKEN",
             r"lepton[_-]?(?:ai[_-]?)?(?:api[_-]?)?token", "https://www.lepton.ai/docs"),
            ("predibase-api-token-v1", "Predibase API token", "predibase", "PREDIBASE_TOKEN",
             r"predibase[_-]?(?:api[_-]?)?token", "https://docs.predibase.com/"),
            ("runway-api-key-v1", "Runway API key", "runway", "RUNWAY_API_KEY",
             r"runway[_-]?(?:ml[_-]?)?(?:api[_-]?)?key", "https://docs.dev.runwayml.com/"),
            ("speechmatics-api-key-v1", "Speechmatics API key", "speechmatics", "SPEECHMATICS_KEY",
             r"speechmatics[_-]?(?:api[_-]?)?key", "https://docs.speechmatics.com/introduction/authentication"),
            ("gladia-api-key-v1", "Gladia API key", "gladia", "GLADIA_API_KEY",
             r"gladia[_-]?(?:api[_-]?)?key", "https://docs.gladia.io/"),
            ("friendliai-token-v1", "FriendliAI token", "friendliai", "FRIENDLIAI_TOKEN",
             r"friendli[_-]?(?:ai[_-]?)?token", "https://docs.friendli.ai/"),
            # DB / backend
            ("fauna-secret-v1", "Fauna secret", "fauna", "FAUNA_SECRET",
             r"fauna[_-]?(?:db[_-]?)?(?:secret|key)", "https://docs.fauna.com/fauna/current/learn/security_model/"),
            ("appwrite-api-key-v1", "Appwrite API key", "appwrite", "APPWRITE_KEY",
             r"appwrite[_-]?(?:api[_-]?)?key", "https://appwrite.io/docs/advanced/platform/api-keys"),
            ("hasura-admin-secret-v1", "Hasura admin secret", "hasura", "HASURA_ADMIN_SECRET",
             r"hasura[_-]?(?:graphql[_-]?)?(?:admin[_-]?)?secret", "https://hasura.io/docs/latest/auth/authentication/admin-secret-access/"),
            ("directus-token-v1", "Directus token", "directus", "DIRECTUS_TOKEN",
             r"directus[_-]?(?:static[_-]?)?token", "https://docs.directus.io/reference/authentication.html"),
            ("convex-deploy-key-v1", "Convex deploy key", "convex", "CONVEX_DEPLOY_KEY",
             r"convex[_-]?(?:deploy[_-]?)?key", "https://docs.convex.dev/production/hosting/"),
            ("turso-api-token-v1", "Turso API token", "turso", "TURSO_TOKEN",
             r"turso[_-]?(?:api[_-]?)?token", "https://docs.turso.tech/api-reference/authentication"),
            ("timescale-api-key-v1", "Timescale API key", "timescale", "TIMESCALE_KEY",
             r"timescale[_-]?(?:api[_-]?)?key", "https://docs.timescale.com/"),
            ("mongodb-atlas-key-v1", "MongoDB Atlas API key", "mongodb", "MONGODB_ATLAS_KEY",
             r"mongodb[_-]?atlas[_-]?(?:private[_-]?|public[_-]?|api[_-]?)?key", "https://www.mongodb.com/docs/atlas/configure-api-access/"),
            # CMS
            ("sanity-token-v1", "Sanity API token", "sanity", "SANITY_TOKEN",
             r"sanity[_-]?(?:api[_-]?)?token", "https://www.sanity.io/docs/http-auth"),
            ("storyblok-token-v1", "Storyblok token", "storyblok", "STORYBLOK_TOKEN",
             r"storyblok[_-]?(?:api[_-]?)?token", "https://www.storyblok.com/docs/api/management/getting-started/authentication"),
            ("datocms-api-token-v1", "DatoCMS API token", "datocms", "DATOCMS_TOKEN",
             r"datocms[_-]?(?:api[_-]?)?token", "https://www.datocms.com/docs/content-management-api/authentication"),
            ("prismic-access-token-v1", "Prismic access token", "prismic", "PRISMIC_TOKEN",
             r"prismic[_-]?(?:access[_-]?)?token", "https://prismic.io/docs/access-token"),
            ("strapi-api-token-v1", "Strapi API token", "strapi", "STRAPI_TOKEN",
             r"strapi[_-]?(?:api[_-]?)?token", "https://docs.strapi.io/dev-docs/api/rest#api-tokens"),
            ("hygraph-token-v1", "Hygraph token", "hygraph", "HYGRAPH_TOKEN",
             r"hygraph[_-]?(?:api[_-]?)?token", "https://hygraph.com/docs/api-reference/basics/authorization"),
            # commerce
            ("squarespace-api-key-v1", "Squarespace API key", "squarespace", "SQUARESPACE_KEY",
             r"squarespace[_-]?(?:api[_-]?)?key", "https://developers.squarespace.com/commerce-apis/authentication"),
            ("ecwid-token-v1", "Ecwid secret token", "ecwid", "ECWID_TOKEN",
             r"ecwid[_-]?(?:secret[_-]?)?token", "https://api-docs.ecwid.com/reference/get-access-token"),
            ("snipcart-api-key-v1", "Snipcart API key", "snipcart", "SNIPCART_KEY",
             r"snipcart[_-]?(?:api[_-]?)?(?:secret[_-]?)?key", "https://docs.snipcart.com/v3/api-reference/introduction"),
            ("swell-secret-key-v1", "Swell secret key", "swell", "SWELL_SECRET_KEY",
             r"swell[_-]?(?:secret[_-]?)?key", "https://developers.swell.is/backend-api/authentication"),
            ("saleor-token-v1", "Saleor app token", "saleor", "SALEOR_TOKEN",
             r"saleor[_-]?(?:app[_-]?|api[_-]?)?token", "https://docs.saleor.io/developer/api-usage/authentication"),
            ("commercetools-secret-v1", "commercetools client secret", "commercetools", "COMMERCETOOLS_SECRET",
             r"commercetools[_-]?(?:client[_-]?)?secret", "https://docs.commercetools.com/api/authorization"),
            # monitoring / ops
            ("sumologic-access-key-v1", "Sumo Logic access key", "sumologic", "SUMOLOGIC_KEY",
             r"sumo[_-]?logic[_-]?(?:access[_-]?)?key", "https://help.sumologic.com/docs/manage/security/access-keys/"),
            ("loggly-token-v1", "Loggly customer token", "loggly", "LOGGLY_TOKEN",
             r"loggly[_-]?(?:customer[_-]?)?token", "https://documentation.solarwinds.com/en/success_center/loggly/content/admin/http-bulk-endpoint.htm"),
            ("papertrail-token-v1", "Papertrail API token", "papertrail", "PAPERTRAIL_TOKEN",
             r"papertrail[_-]?(?:api[_-]?)?token", "https://www.papertrail.com/help/rest-api/"),
            ("highlight-api-key-v1", "Highlight.io API key", "highlight", "HIGHLIGHT_KEY",
             r"highlight[_-]?(?:io[_-]?)?(?:api[_-]?)?key", "https://www.highlight.io/docs"),
            ("checkly-api-key-v1", "Checkly API key", "checkly", "CHECKLY_KEY",
             r"checkly[_-]?(?:api[_-]?)?key", "https://developers.checklyhq.com/reference/authentication"),
            ("pingdom-api-token-v1", "Pingdom API token", "pingdom", "PINGDOM_TOKEN",
             r"pingdom[_-]?(?:api[_-]?)?token", "https://docs.pingdom.com/api/"),
            ("victorops-api-key-v1", "VictorOps API key", "victorops", "VICTOROPS_KEY",
             r"victorops[_-]?(?:api[_-]?)?key", "https://help.victorops.com/knowledge-base/api/"),
            # cloud / hosting
            ("aiven-token-v1", "Aiven API token", "aiven", "AIVEN_TOKEN",
             r"aiven[_-]?(?:api[_-]?)?token", "https://docs.aiven.io/docs/tools/api"),
            ("civo-api-key-v1", "Civo API key", "civo", "CIVO_API_KEY",
             r"civo[_-]?(?:api[_-]?)?key", "https://www.civo.com/docs/account/api-keys"),
            ("exoscale-api-key-v1", "Exoscale API key", "exoscale", "EXOSCALE_KEY",
             r"exoscale[_-]?(?:api[_-]?)?(?:key|secret)", "https://openapi-v2.exoscale.com/"),
            ("ionos-token-v1", "IONOS API token", "ionos", "IONOS_TOKEN",
             r"ionos[_-]?(?:api[_-]?)?token", "https://api.ionos.com/docs/"),
            ("koyeb-api-token-v1", "Koyeb API token", "koyeb", "KOYEB_TOKEN",
             r"koyeb[_-]?(?:api[_-]?)?token", "https://www.koyeb.com/docs/reference/api"),
            ("deta-project-key-v1", "Deta project key", "deta", "DETA_PROJECT_KEY",
             r"deta[_-]?(?:project[_-]?)?key", "https://deta.space/docs/en/reference/deta_base/about"),
        ]),

        # ---- twenty-third batch: CI / auth / maps / web3 / media / CDN ----
        *_labelled_batch([
            # CI / CD
            ("teamcity-token-v1", "TeamCity access token", "teamcity", "TEAMCITY_TOKEN",
             r"teamcity[_-]?(?:api[_-]?)?token", "https://www.jetbrains.com/help/teamcity/rest-api.html"),
            ("drone-ci-token-v1", "Drone CI token", "drone", "DRONE_TOKEN",
             r"drone[_-]?(?:ci[_-]?)?token", "https://docs.drone.io/api/overview/"),
            ("semaphore-api-token-v1", "Semaphore API token", "semaphore", "SEMAPHORE_TOKEN",
             r"semaphore[_-]?(?:api[_-]?)?token", "https://docs.semaphoreci.com/reference/api-v1alpha/"),
            ("appveyor-token-v1", "AppVeyor API token", "appveyor", "APPVEYOR_TOKEN",
             r"appveyor[_-]?(?:api[_-]?)?token", "https://www.appveyor.com/docs/api/"),
            ("bitrise-token-v1", "Bitrise access token", "bitrise", "BITRISE_TOKEN",
             r"bitrise[_-]?(?:api[_-]?)?token", "https://devcenter.bitrise.io/en/api.html"),
            ("codemagic-token-v1", "Codemagic API token", "codemagic", "CODEMAGIC_TOKEN",
             r"codemagic[_-]?(?:api[_-]?)?token", "https://docs.codemagic.io/rest-api/overview/"),
            ("codefresh-api-key-v1", "Codefresh API key", "codefresh", "CODEFRESH_KEY",
             r"codefresh[_-]?(?:api[_-]?)?key", "https://codefresh.io/docs/docs/integrations/codefresh-api/"),
            ("octopus-deploy-key-v1", "Octopus Deploy API key", "octopus", "OCTOPUS_API_KEY",
             r"octopus[_-]?(?:deploy[_-]?)?(?:api[_-]?)?key", "https://octopus.com/docs/octopus-rest-api/how-to-create-an-api-key"),
            # auth / identity
            ("workos-api-key-v1", "WorkOS API key", "workos", "WORKOS_API_KEY",
             r"workos[_-]?(?:api[_-]?)?key", "https://workos.com/docs/reference/authentication"),
            ("supertokens-api-key-v1", "SuperTokens API key", "supertokens", "SUPERTOKENS_KEY",
             r"supertokens[_-]?(?:api[_-]?)?key", "https://supertokens.com/docs/"),
            ("frontegg-client-secret-v1", "Frontegg client secret", "frontegg", "FRONTEGG_SECRET",
             r"frontegg[_-]?(?:client[_-]?)?secret", "https://docs.frontegg.com/docs/api-token-types"),
            ("kinde-client-secret-v1", "Kinde client secret", "kinde", "KINDE_SECRET",
             r"kinde[_-]?(?:client[_-]?)?secret", "https://docs.kinde.com/developer-tools/your-apis/register-manage-apis/"),
            ("descope-management-key-v1", "Descope management key", "descope", "DESCOPE_KEY",
             r"descope[_-]?(?:management[_-]?|api[_-]?)?key", "https://docs.descope.com/management/company/managementkeys"),
            ("fusionauth-api-key-v1", "FusionAuth API key", "fusionauth", "FUSIONAUTH_KEY",
             r"fusionauth[_-]?(?:api[_-]?)?key", "https://fusionauth.io/docs/apis/authentication"),
            ("keycloak-client-secret-v1", "Keycloak client secret", "keycloak", "KEYCLOAK_SECRET",
             r"keycloak[_-]?(?:client[_-]?)?secret", "https://www.keycloak.org/docs/latest/securing_apps/"),
            ("authentik-token-v1", "Authentik API token", "authentik", "AUTHENTIK_TOKEN",
             r"authentik[_-]?(?:api[_-]?)?token", "https://docs.goauthentik.io/docs/developer-docs/api/"),
            # maps / geo
            ("mapbox-secret-token-v1", "Mapbox secret token", "mapbox", "MAPBOX_SECRET_TOKEN",
             r"mapbox[_-]?(?:secret[_-]?)?token", "https://docs.mapbox.com/api/accounts/tokens/"),
            ("tomtom-api-key-v1", "TomTom API key", "tomtom", "TOMTOM_KEY",
             r"tomtom[_-]?(?:api[_-]?)?key", "https://developer.tomtom.com/knowledgebase/platform/articles/how-to-get-an-tomtom-api-key/"),
            ("maptiler-api-key-v1", "MapTiler API key", "maptiler", "MAPTILER_KEY",
             r"maptiler[_-]?(?:api[_-]?)?key", "https://docs.maptiler.com/cloud/api/authentication-key/"),
            ("geoapify-api-key-v1", "Geoapify API key", "geoapify", "GEOAPIFY_KEY",
             r"geoapify[_-]?(?:api[_-]?)?key", "https://apidocs.geoapify.com/"),
            ("radar-secret-key-v1", "Radar secret key", "radar", "RADAR_SECRET_KEY",
             r"radar[_-]?(?:secret[_-]?)?key", "https://radar.com/documentation/api"),
            ("opencage-api-key-v1", "OpenCage API key", "opencage", "OPENCAGE_KEY",
             r"opencage[_-]?(?:api[_-]?)?key", "https://opencagedata.com/api"),
            # web3 / crypto
            ("infura-api-key-v1", "Infura API key", "infura", "INFURA_KEY",
             r"infura[_-]?(?:api[_-]?|project[_-]?)?(?:key|secret|id)", "https://docs.infura.io/api/getting-started"),
            ("alchemy-api-key-v1", "Alchemy API key", "alchemy", "ALCHEMY_KEY",
             r"alchemy[_-]?(?:api[_-]?)?key", "https://docs.alchemy.com/docs/how-to-create-an-app"),
            ("quicknode-api-key-v1", "QuickNode API key", "quicknode", "QUICKNODE_KEY",
             r"quicknode[_-]?(?:api[_-]?)?key", "https://www.quicknode.com/docs/welcome"),
            ("moralis-api-key-v1", "Moralis API key", "moralis", "MORALIS_KEY",
             r"moralis[_-]?(?:api[_-]?)?key", "https://docs.moralis.com/web3-data-api/evm/get-your-api-key"),
            ("thirdweb-secret-key-v1", "thirdweb secret key", "thirdweb", "THIRDWEB_SECRET_KEY",
             r"thirdweb[_-]?(?:secret[_-]?)?key", "https://portal.thirdweb.com/account/api-keys"),
            ("etherscan-api-key-v1", "Etherscan API key", "etherscan", "ETHERSCAN_KEY",
             r"etherscan[_-]?(?:api[_-]?)?key", "https://docs.etherscan.io/getting-started/viewing-api-usage-statistics"),
            ("coinmarketcap-api-key-v1", "CoinMarketCap API key", "coinmarketcap", "COINMARKETCAP_KEY",
             r"coinmarketcap[_-]?(?:api[_-]?)?key", "https://coinmarketcap.com/api/documentation/v1/"),
            ("coinbase-api-secret-v1", "Coinbase API secret", "coinbase", "COINBASE_SECRET",
             r"coinbase[_-]?(?:api[_-]?)?secret", "https://docs.cdp.coinbase.com/"),
            ("tatum-api-key-v1", "Tatum API key", "tatum", "TATUM_KEY",
             r"tatum[_-]?(?:api[_-]?)?key", "https://docs.tatum.io/"),
            # media / data APIs
            ("openweather-api-key-v1", "OpenWeather API key", "openweather", "OPENWEATHER_KEY",
             r"openweather[_-]?(?:map[_-]?)?(?:api[_-]?)?key", "https://openweathermap.org/appid"),
            ("giphy-api-key-v1", "Giphy API key", "giphy", "GIPHY_KEY",
             r"giphy[_-]?(?:api[_-]?)?key", "https://developers.giphy.com/docs/api/"),
            ("unsplash-access-key-v1", "Unsplash access key", "unsplash", "UNSPLASH_KEY",
             r"unsplash[_-]?(?:access[_-]?)?key", "https://unsplash.com/documentation#authorization"),
            ("pexels-api-key-v1", "Pexels API key", "pexels", "PEXELS_KEY",
             r"pexels[_-]?(?:api[_-]?)?key", "https://www.pexels.com/api/documentation/"),
            ("pixabay-api-key-v1", "Pixabay API key", "pixabay", "PIXABAY_KEY",
             r"pixabay[_-]?(?:api[_-]?)?key", "https://pixabay.com/api/docs/"),
            ("tmdb-api-key-v1", "TMDB API key", "tmdb", "TMDB_KEY",
             r"tmdb[_-]?(?:api[_-]?)?(?:key|token)", "https://developer.themoviedb.org/docs/getting-started"),
            ("vimeo-access-token-v1", "Vimeo access token", "vimeo", "VIMEO_TOKEN",
             r"vimeo[_-]?(?:access[_-]?)?token", "https://developer.vimeo.com/api/authentication"),
            # CDN / registries
            ("keycdn-api-key-v1", "KeyCDN API key", "keycdn", "KEYCDN_KEY",
             r"keycdn[_-]?(?:api[_-]?)?key", "https://www.keycdn.com/api"),
            ("gcore-api-token-v1", "Gcore API token", "gcore", "GCORE_TOKEN",
             r"gcore[_-]?(?:api[_-]?)?token", "https://api.gcore.com/docs/iam"),
            ("packagecloud-token-v1", "packagecloud API token", "packagecloud", "PACKAGECLOUD_TOKEN",
             r"packagecloud[_-]?(?:api[_-]?)?token", "https://packagecloud.io/docs/api"),
            ("gemfury-push-token-v1", "Gemfury push token", "gemfury", "GEMFURY_TOKEN",
             r"gemfury[_-]?(?:push[_-]?)?token", "https://gemfury.com/help/pushing-packages/"),
        ]),

        # ---- twenty-fourth batch: productivity / e-sign / video / QA / flags ----
        *_labelled_batch([
            # productivity / docs
            ("monday-api-token-v1", "Monday.com API token", "monday", "MONDAY_TOKEN",
             r"monday[_-]?(?:com[_-]?)?(?:api[_-]?)?token", "https://developer.monday.com/api-reference/docs/authentication"),
            ("basecamp-token-v1", "Basecamp access token", "basecamp", "BASECAMP_TOKEN",
             r"basecamp[_-]?(?:access[_-]?)?token", "https://github.com/basecamp/bc3-api"),
            ("wrike-token-v1", "Wrike API token", "wrike", "WRIKE_TOKEN",
             r"wrike[_-]?(?:api[_-]?)?token", "https://developers.wrike.com/oauth-20-authorization/"),
            ("teamwork-api-key-v1", "Teamwork API key", "teamwork", "TEAMWORK_KEY",
             r"teamwork[_-]?(?:api[_-]?)?key", "https://apidocs.teamwork.com/guides/teamwork/authentication"),
            ("miro-access-token-v1", "Miro access token", "miro", "MIRO_TOKEN",
             r"miro[_-]?(?:access[_-]?)?token", "https://developers.miro.com/docs/getting-started-with-oauth"),
            ("mural-api-token-v1", "Mural API token", "mural", "MURAL_TOKEN",
             r"mural[_-]?(?:api[_-]?)?token", "https://developers.mural.co/public/docs/authorization"),
            ("productboard-token-v1", "Productboard API token", "productboard", "PRODUCTBOARD_TOKEN",
             r"productboard[_-]?(?:api[_-]?)?token", "https://developer.productboard.com/"),
            ("getguru-token-v1", "Guru API token", "getguru", "GURU_TOKEN",
             r"getguru[_-]?(?:api[_-]?)?token", "https://developer.getguru.com/docs/getting-started"),
            # e-sign / documents
            ("docusign-integration-key-v1", "DocuSign integration key", "docusign", "DOCUSIGN_KEY",
             r"docusign[_-]?(?:integration[_-]?|api[_-]?)?key", "https://developers.docusign.com/platform/auth/"),
            ("hellosign-api-key-v1", "Dropbox Sign (HelloSign) API key", "hellosign", "HELLOSIGN_KEY",
             r"hellosign[_-]?(?:api[_-]?)?key", "https://developers.hellosign.com/api/reference/authentication/"),
            ("pandadoc-api-key-v1", "PandaDoc API key", "pandadoc", "PANDADOC_KEY",
             r"pandadoc[_-]?(?:api[_-]?)?key", "https://developers.pandadoc.com/reference/authentication-process"),
            ("signnow-api-token-v1", "SignNow API token", "signnow", "SIGNNOW_TOKEN",
             r"signnow[_-]?(?:api[_-]?)?token", "https://docs.signnow.com/docs/signnow/welcome"),
            # calendar / scheduling
            ("calendly-token-v1", "Calendly API token", "calendly", "CALENDLY_TOKEN",
             r"calendly[_-]?(?:api[_-]?)?token", "https://developer.calendly.com/api-docs"),
            ("savvycal-token-v1", "SavvyCal API token", "savvycal", "SAVVYCAL_TOKEN",
             r"savvycal[_-]?(?:api[_-]?)?token", "https://savvycal.com/developers"),
            ("acuity-api-key-v1", "Acuity Scheduling API key", "acuity", "ACUITY_KEY",
             r"acuity[_-]?(?:scheduling[_-]?)?(?:api[_-]?)?key", "https://developers.acuityscheduling.com/docs/authentication"),
            # video / media
            ("livepeer-api-key-v1", "Livepeer API key", "livepeer", "LIVEPEER_KEY",
             r"livepeer[_-]?(?:api[_-]?)?key", "https://docs.livepeer.org/"),
            ("apivideo-api-key-v1", "api.video API key", "apivideo", "APIVIDEO_KEY",
             r"api[_-]?video[_-]?(?:api[_-]?)?key", "https://docs.api.video/reference/api/Authentication"),
            ("daily-api-key-v1", "Daily.co API key", "daily", "DAILY_API_KEY",
             r"daily[_-]?(?:co[_-]?)?(?:api[_-]?)?key", "https://docs.daily.co/reference/rest-api"),
            ("wistia-api-token-v1", "Wistia API token", "wistia", "WISTIA_TOKEN",
             r"wistia[_-]?(?:api[_-]?)?(?:token|password)", "https://docs.wistia.com/docs/authentication-and-access-tokens"),
            ("brightcove-client-secret-v1", "Brightcove client secret", "brightcove", "BRIGHTCOVE_SECRET",
             r"brightcove[_-]?(?:client[_-]?)?secret", "https://apis.support.brightcove.com/general/authentication/index.html"),
            ("jwplayer-api-secret-v1", "JW Player API secret", "jwplayer", "JWPLAYER_SECRET",
             r"jwplayer[_-]?(?:api[_-]?)?secret", "https://docs.jwplayer.com/platform/reference/authentication"),
            # testing / QA
            ("browserstack-access-key-v1", "BrowserStack access key", "browserstack", "BROWSERSTACK_KEY",
             r"browserstack[_-]?(?:access[_-]?)?key", "https://www.browserstack.com/docs/automate/selenium/getting-started/nodejs"),
            ("saucelabs-access-key-v1", "Sauce Labs access key", "saucelabs", "SAUCELABS_KEY",
             r"sauce[_-]?labs[_-]?(?:access[_-]?)?key", "https://docs.saucelabs.com/basics/acct-team-mgmt/managing-user-info/"),
            ("lambdatest-access-key-v1", "LambdaTest access key", "lambdatest", "LAMBDATEST_KEY",
             r"lambdatest[_-]?(?:access[_-]?)?key", "https://www.lambdatest.com/support/docs/api-doc/"),
            ("percy-token-v1", "Percy token", "percy", "PERCY_TOKEN",
             r"percy[_-]?token", "https://www.browserstack.com/docs/percy/get-started/set-env-var"),
            ("applitools-api-key-v1", "Applitools API key", "applitools", "APPLITOOLS_KEY",
             r"applitools[_-]?(?:api[_-]?)?key", "https://applitools.com/docs/topics/overview/obtain-api-key.html"),
            ("cypress-record-key-v1", "Cypress record key", "cypress", "CYPRESS_RECORD_KEY",
             r"cypress[_-]?(?:record[_-]?)?key", "https://docs.cypress.io/guides/cloud/account-management/projects"),
            ("testrail-api-key-v1", "TestRail API key", "testrail", "TESTRAIL_KEY",
             r"testrail[_-]?(?:api[_-]?)?key", "https://support.testrail.com/hc/en-us/articles/7077196481428-Accessing-the-TestRail-API"),
            # feature flags / config
            ("flagsmith-key-v1", "Flagsmith environment key", "flagsmith", "FLAGSMITH_KEY",
             r"flagsmith[_-]?(?:environment[_-]?|api[_-]?)?key", "https://docs.flagsmith.com/clients/rest"),
            ("splitio-api-key-v1", "Split.io API key", "split", "SPLITIO_KEY",
             r"split[_-]?io[_-]?(?:sdk[_-]?|api[_-]?)?key", "https://docs.split.io/reference/authentication"),
            ("configcat-sdk-key-v1", "ConfigCat SDK key", "configcat", "CONFIGCAT_KEY",
             r"configcat[_-]?(?:sdk[_-]?)?key", "https://configcat.com/docs/"),
            ("unleash-api-token-v1", "Unleash API token", "unleash", "UNLEASH_TOKEN",
             r"unleash[_-]?(?:api[_-]?)?token", "https://docs.getunleash.io/reference/api-tokens-and-client-keys"),
            ("statsig-server-secret-v1", "Statsig server secret", "statsig", "STATSIG_SECRET",
             r"statsig[_-]?(?:server[_-]?)?secret", "https://docs.statsig.com/sdk-keys/api-keys/"),
            ("optimizely-sdk-key-v1", "Optimizely SDK/API key", "optimizely", "OPTIMIZELY_KEY",
             r"optimizely[_-]?(?:sdk[_-]?|api[_-]?)?(?:key|token)", "https://docs.developers.optimizely.com/feature-experimentation/docs/authentication"),
            ("devcycle-server-key-v1", "DevCycle server SDK key", "devcycle", "DEVCYCLE_KEY",
             r"devcycle[_-]?(?:server[_-]?)?(?:sdk[_-]?)?key", "https://docs.devcycle.com/sdk/"),
            # support
            ("kustomer-api-key-v1", "Kustomer API key", "kustomer", "KUSTOMER_KEY",
             r"kustomer[_-]?(?:api[_-]?)?key", "https://developer.kustomer.com/kustomer-api-docs/reference/authentication"),
            ("crisp-api-key-v1", "Crisp API key", "crisp", "CRISP_KEY",
             r"crisp[_-]?(?:api[_-]?)?(?:identifier|key)", "https://docs.crisp.chat/references/rest-api/v1/"),
        ]),

        # ---- twenty-fifth batch: automation / enrichment / finance / SMS / social ----
        *_labelled_batch([
            # automation / workflow / infra
            ("n8n-api-key-v1", "n8n API key", "n8n", "N8N_API_KEY",
             r"n8n[_-]?(?:api[_-]?)?key", "https://docs.n8n.io/api/authentication/"),
            ("tray-api-token-v1", "Tray.io API token", "tray", "TRAY_TOKEN",
             r"tray[_-]?(?:io[_-]?)?(?:api[_-]?)?token", "https://tray.io/documentation/embedded/getting-started/authentication/"),
            ("workato-api-token-v1", "Workato API token", "workato", "WORKATO_TOKEN",
             r"workato[_-]?(?:api[_-]?)?token", "https://docs.workato.com/oem/oem-api.html"),
            ("pipedream-api-key-v1", "Pipedream API key", "pipedream", "PIPEDREAM_KEY",
             r"pipedream[_-]?(?:api[_-]?)?key", "https://pipedream.com/docs/rest-api/auth/"),
            ("retool-api-token-v1", "Retool API token", "retool", "RETOOL_TOKEN",
             r"retool[_-]?(?:api[_-]?)?token", "https://docs.retool.com/org-users/guides/retool-api"),
            ("temporal-api-key-v1", "Temporal Cloud API key", "temporal", "TEMPORAL_API_KEY",
             r"temporal[_-]?(?:cloud[_-]?)?(?:api[_-]?)?key", "https://docs.temporal.io/cloud/api-keys"),
            ("inngest-signing-key-v1", "Inngest signing key", "inngest", "INNGEST_KEY",
             r"inngest[_-]?(?:event[_-]?|signing[_-]?)?key", "https://www.inngest.com/docs/platform/signing-keys"),
            ("triggerdev-api-key-v1", "Trigger.dev API key", "trigger", "TRIGGERDEV_KEY",
             r"trigger[_-]?(?:dev[_-]?)?(?:api[_-]?)?key", "https://trigger.dev/docs/apikeys"),
            ("hookdeck-api-key-v1", "Hookdeck API key", "hookdeck", "HOOKDECK_KEY",
             r"hookdeck[_-]?(?:api[_-]?)?key", "https://hookdeck.com/docs/api"),
            ("svix-auth-token-v1", "Svix auth token", "svix", "SVIX_TOKEN",
             r"svix[_-]?(?:api[_-]?|auth[_-]?)?token", "https://docs.svix.com/api-keys"),
            # email validation
            ("hunter-api-key-v1", "Hunter.io API key", "hunter", "HUNTER_KEY",
             r"hunter[_-]?(?:io[_-]?)?(?:api[_-]?)?key", "https://hunter.io/api-documentation/v2"),
            ("neverbounce-api-key-v1", "NeverBounce API key", "neverbounce", "NEVERBOUNCE_KEY",
             r"neverbounce[_-]?(?:api[_-]?)?key", "https://developers.neverbounce.com/"),
            ("zerobounce-api-key-v1", "ZeroBounce API key", "zerobounce", "ZEROBOUNCE_KEY",
             r"zerobounce[_-]?(?:api[_-]?)?key", "https://www.zerobounce.net/docs/"),
            ("kickbox-api-key-v1", "Kickbox API key", "kickbox", "KICKBOX_KEY",
             r"kickbox[_-]?(?:api[_-]?)?key", "https://docs.kickbox.com/docs/using-the-api"),
            ("abstractapi-key-v1", "AbstractAPI key", "abstractapi", "ABSTRACTAPI_KEY",
             r"abstractapi[_-]?(?:api[_-]?)?key", "https://docs.abstractapi.com/"),
            # data enrichment
            ("clearbit-api-key-v1", "Clearbit API key", "clearbit", "CLEARBIT_KEY",
             r"clearbit[_-]?(?:api[_-]?)?key", "https://dashboard.clearbit.com/docs"),
            ("fullcontact-api-key-v1", "FullContact API key", "fullcontact", "FULLCONTACT_KEY",
             r"fullcontact[_-]?(?:api[_-]?)?key", "https://docs.fullcontact.com/docs/getting-started"),
            ("peopledatalabs-api-key-v1", "People Data Labs API key", "peopledatalabs", "PDL_KEY",
             r"peopledatalabs[_-]?(?:api[_-]?)?key", "https://docs.peopledatalabs.com/docs/authentication"),
            ("rocketreach-api-key-v1", "RocketReach API key", "rocketreach", "ROCKETREACH_KEY",
             r"rocketreach[_-]?(?:api[_-]?)?key", "https://rocketreach.co/api/v2/docs"),
            ("lusha-api-key-v1", "Lusha API key", "lusha", "LUSHA_KEY",
             r"lusha[_-]?(?:api[_-]?)?key", "https://www.lusha.com/docs/"),
            # finance data
            ("polygon-api-key-v1", "Polygon.io API key", "polygon", "POLYGON_KEY",
             r"polygon[_-]?(?:io[_-]?)?(?:api[_-]?)?key", "https://polygon.io/docs/stocks/getting-started"),
            ("alphavantage-api-key-v1", "Alpha Vantage API key", "alphavantage", "ALPHAVANTAGE_KEY",
             r"alphavantage[_-]?(?:api[_-]?)?key", "https://www.alphavantage.co/documentation/"),
            ("iexcloud-token-v1", "IEX Cloud token", "iex", "IEXCLOUD_TOKEN",
             r"iex[_-]?(?:cloud[_-]?)?(?:api[_-]?)?(?:token|key)", "https://iexcloud.io/docs/"),
            ("twelvedata-api-key-v1", "Twelve Data API key", "twelvedata", "TWELVEDATA_KEY",
             r"twelvedata[_-]?(?:api[_-]?)?key", "https://twelvedata.com/docs"),
            ("marketstack-api-key-v1", "Marketstack API key", "marketstack", "MARKETSTACK_KEY",
             r"marketstack[_-]?(?:api[_-]?)?key", "https://marketstack.com/documentation"),
            ("tiingo-api-token-v1", "Tiingo API token", "tiingo", "TIINGO_TOKEN",
             r"tiingo[_-]?(?:api[_-]?)?(?:token|key)", "https://www.tiingo.com/documentation/general/overview"),
            # SMS / voice
            ("clicksend-api-key-v1", "ClickSend API key", "clicksend", "CLICKSEND_KEY",
             r"clicksend[_-]?(?:api[_-]?)?key", "https://developers.clicksend.com/docs/rest/v3/"),
            ("textmagic-api-key-v1", "TextMagic API key", "textmagic", "TEXTMAGIC_KEY",
             r"textmagic[_-]?(?:api[_-]?)?key", "https://docs.textmagic.com/"),
            ("telesign-api-key-v1", "TeleSign API key", "telesign", "TELESIGN_KEY",
             r"telesign[_-]?(?:api[_-]?|customer[_-]?)?key", "https://developer.telesign.com/enterprise/docs/authentication"),
            # social
            ("reddit-client-secret-v1", "Reddit client secret", "reddit", "REDDIT_SECRET",
             r"reddit[_-]?(?:client[_-]?)?secret", "https://github.com/reddit-archive/reddit/wiki/OAuth2"),
            ("linkedin-client-secret-v1", "LinkedIn client secret", "linkedin", "LINKEDIN_SECRET",
             r"linkedin[_-]?(?:client[_-]?)?secret", "https://learn.microsoft.com/en-us/linkedin/shared/authentication/authentication"),
            ("pinterest-access-token-v1", "Pinterest access token", "pinterest", "PINTEREST_TOKEN",
             r"pinterest[_-]?(?:access[_-]?)?token", "https://developers.pinterest.com/docs/getting-started/authentication/"),
            ("tiktok-client-secret-v1", "TikTok client secret", "tiktok", "TIKTOK_SECRET",
             r"tiktok[_-]?(?:client[_-]?)?(?:key|secret)", "https://developers.tiktok.com/doc/oauth-user-access-token-management"),
            ("snapchat-client-secret-v1", "Snapchat client secret", "snapchat", "SNAPCHAT_SECRET",
             r"snapchat[_-]?(?:client[_-]?)?secret", "https://developers.snap.com/api/marketing-api/Ads-API/authentication"),
            ("mastodon-access-token-v1", "Mastodon access token", "mastodon", "MASTODON_TOKEN",
             r"mastodon[_-]?(?:access[_-]?)?token", "https://docs.joinmastodon.org/client/token/"),
            ("buffer-access-token-v1", "Buffer access token", "buffer", "BUFFER_TOKEN",
             r"buffer[_-]?(?:access[_-]?)?token", "https://buffer.com/developers/api"),
            ("hootsuite-token-v1", "Hootsuite access token", "hootsuite", "HOOTSUITE_TOKEN",
             r"hootsuite[_-]?(?:access[_-]?)?token", "https://developer.hootsuite.com/docs/authentication"),
        ]),

        # ---- twenty-sixth batch: IoT / gaming / transport / MLops / billing / shipping ----
        *_labelled_batch([
            # IoT / hardware
            ("particle-access-token-v1", "Particle access token", "particle", "PARTICLE_TOKEN",
             r"particle[_-]?(?:access[_-]?)?token", "https://docs.particle.io/reference/cloud-apis/api/"),
            ("blynk-auth-token-v1", "Blynk auth token", "blynk", "BLYNK_TOKEN",
             r"blynk[_-]?(?:auth[_-]?)?token", "https://docs.blynk.io/en/blynk.cloud/troubleshooting"),
            ("balena-api-key-v1", "Balena API key", "balena", "BALENA_KEY",
             r"balena[_-]?(?:api[_-]?)?(?:key|token)", "https://docs.balena.io/learn/manage/api-keys/"),
            ("golioth-api-key-v1", "Golioth API key", "golioth", "GOLIOTH_KEY",
             r"golioth[_-]?(?:api[_-]?)?key", "https://docs.golioth.io/reference/rest-api/"),
            ("thingspeak-api-key-v1", "ThingSpeak API key", "thingspeak", "THINGSPEAK_KEY",
             r"thingspeak[_-]?(?:api[_-]?)?key", "https://www.mathworks.com/help/thingspeak/rest-api.html"),
            ("arduino-cloud-secret-v1", "Arduino IoT Cloud client secret", "arduino", "ARDUINO_SECRET",
             r"arduino[_-]?(?:cloud[_-]?)?(?:client[_-]?)?secret", "https://docs.arduino.cc/arduino-cloud/api/api-overview/"),
            # gaming
            ("steam-web-api-key-v1", "Steam Web API key", "steam", "STEAM_KEY",
             r"steam[_-]?(?:web[_-]?)?(?:api[_-]?)?key", "https://steamcommunity.com/dev"),
            ("riot-api-key-v1", "Riot Games API key", "riot", "RIOT_KEY",
             r"riot[_-]?(?:games[_-]?)?(?:api[_-]?)?key", "https://developer.riotgames.com/"),
            ("unity-cloud-key-v1", "Unity Cloud API key", "unity", "UNITY_KEY",
             r"unity[_-]?(?:cloud[_-]?)?(?:api[_-]?)?key", "https://services.docs.unity.com/"),
            ("playfab-secret-key-v1", "PlayFab secret key", "playfab", "PLAYFAB_SECRET",
             r"playfab[_-]?(?:secret[_-]?)?key", "https://learn.microsoft.com/en-us/gaming/playfab/"),
            ("epic-games-secret-v1", "Epic Games client secret", "epic", "EPIC_SECRET",
             r"epic[_-]?(?:games[_-]?)?(?:client[_-]?)?secret", "https://dev.epicgames.com/docs/web-api-ref/authentication"),
            # transport / travel
            ("uber-client-secret-v1", "Uber client secret", "uber", "UBER_SECRET",
             r"uber[_-]?(?:client[_-]?)?secret", "https://developer.uber.com/docs/riders/guides/authentication/introduction"),
            ("lyft-client-secret-v1", "Lyft client secret", "lyft", "LYFT_SECRET",
             r"lyft[_-]?(?:client[_-]?)?secret", "https://developer.lyft.com/docs/authentication"),
            ("amadeus-api-secret-v1", "Amadeus API secret", "amadeus", "AMADEUS_SECRET",
             r"amadeus[_-]?(?:api[_-]?)?secret", "https://developers.amadeus.com/self-service/apis-docs/guides/authorization-262"),
            ("flightaware-api-key-v1", "FlightAware API key", "flightaware", "FLIGHTAWARE_KEY",
             r"flightaware[_-]?(?:api[_-]?)?key", "https://www.flightaware.com/aeroapi/portal/documentation"),
            ("aviationstack-api-key-v1", "Aviationstack API key", "aviationstack", "AVIATIONSTACK_KEY",
             r"aviationstack[_-]?(?:api[_-]?)?key", "https://aviationstack.com/documentation"),
            # conferencing
            ("zoom-client-secret-v1", "Zoom client secret", "zoom", "ZOOM_SECRET",
             r"zoom[_-]?(?:client[_-]?)?secret", "https://developers.zoom.us/docs/internal-apps/s2s-oauth/"),
            # ML ops / data labelling
            ("mlflow-token-v1", "MLflow tracking token", "mlflow", "MLFLOW_TOKEN",
             r"mlflow[_-]?(?:tracking[_-]?)?token", "https://mlflow.org/docs/latest/auth/index.html"),
            ("cometml-api-key-v1", "Comet ML API key", "comet", "COMETML_KEY",
             r"comet[_-]?(?:ml[_-]?)?(?:api[_-]?)?key", "https://www.comet.com/docs/v2/guides/getting-started/configure-comet/"),
            ("neptune-api-token-v1", "Neptune.ai API token", "neptune", "NEPTUNE_TOKEN",
             r"neptune[_-]?(?:api[_-]?)?token", "https://docs.neptune.ai/setup/setting_api_token/"),
            ("clearml-access-key-v1", "ClearML access key", "clearml", "CLEARML_KEY",
             r"clearml[_-]?(?:access[_-]?|secret[_-]?)?key", "https://clear.ml/docs/latest/docs/"),
            ("roboflow-api-key-v1", "Roboflow API key", "roboflow", "ROBOFLOW_KEY",
             r"roboflow[_-]?(?:api[_-]?)?key", "https://docs.roboflow.com/api-reference/authentication"),
            ("labelbox-api-key-v1", "Labelbox API key", "labelbox", "LABELBOX_KEY",
             r"labelbox[_-]?(?:api[_-]?)?key", "https://docs.labelbox.com/reference/create-api-key"),
            # search
            ("swiftype-api-key-v1", "Swiftype API key", "swiftype", "SWIFTYPE_KEY",
             r"swiftype[_-]?(?:api[_-]?)?key", "https://swiftype.com/documentation/site-search/overview"),
            ("addsearch-api-key-v1", "AddSearch API key", "addsearch", "ADDSEARCH_KEY",
             r"addsearch[_-]?(?:api[_-]?)?key", "https://www.addsearch.com/docs/api/overview/"),
            ("coveo-api-key-v1", "Coveo API key", "coveo", "COVEO_KEY",
             r"coveo[_-]?(?:api[_-]?)?key", "https://docs.coveo.com/en/1718/"),
            # billing / metering
            ("chargify-api-key-v1", "Chargify (Maxio) API key", "chargify", "CHARGIFY_KEY",
             r"chargify[_-]?(?:api[_-]?)?key", "https://developers.chargify.com/docs/developer-docs/"),
            ("metronome-api-token-v1", "Metronome API token", "metronome", "METRONOME_TOKEN",
             r"metronome[_-]?(?:api[_-]?)?(?:key|token)", "https://docs.metronome.com/developer-resources/authentication/"),
            ("lago-api-key-v1", "Lago API key", "lago", "LAGO_KEY",
             r"lago[_-]?(?:api[_-]?)?key", "https://docs.getlago.com/api-reference/intro"),
            ("revenuecat-secret-key-v1", "RevenueCat secret key", "revenuecat", "REVENUECAT_SECRET",
             r"revenuecat[_-]?(?:api[_-]?|secret[_-]?)?key", "https://www.revenuecat.com/docs/api-v1"),
            ("adapty-secret-key-v1", "Adapty secret key", "adapty", "ADAPTY_SECRET",
             r"adapty[_-]?(?:secret[_-]?)?key", "https://adapty.io/docs/"),
            # shipping / logistics
            ("shipstation-api-key-v1", "ShipStation API key", "shipstation", "SHIPSTATION_KEY",
             r"shipstation[_-]?(?:api[_-]?)?(?:key|secret)", "https://www.shipstation.com/docs/api/requirements/"),
            ("aftership-api-key-v1", "AfterShip API key", "aftership", "AFTERSHIP_KEY",
             r"aftership[_-]?(?:api[_-]?)?key", "https://www.aftership.com/docs/tracking/quickstart/authentication"),
            ("shipengine-api-key-v1", "ShipEngine API key", "shipengine", "SHIPENGINE_KEY",
             r"shipengine[_-]?(?:api[_-]?)?key", "https://www.shipengine.com/docs/auth/"),
            ("sendcloud-api-key-v1", "Sendcloud API key", "sendcloud", "SENDCLOUD_KEY",
             r"sendcloud[_-]?(?:api[_-]?)?(?:key|secret)", "https://api.sendcloud.dev/docs/sendcloud-public-api/authentication"),
        ]),

        # ---- twenty-seventh batch: cloud / DNS / email / monitoring / notify / pay / auth ----
        *_labelled_batch([
            # cloud / hosting
            ("vmware-cloud-token-v1", "VMware Cloud API token", "vmware", "VMWARE_TOKEN",
             r"vmware[_-]?(?:cloud[_-]?)?(?:api[_-]?)?token", "https://developer.vmware.com/apis"),
            ("equinix-metal-token-v1", "Equinix Metal API token", "equinix", "EQUINIX_TOKEN",
             r"equinix[_-]?(?:metal[_-]?)?(?:api[_-]?)?token", "https://deploy.equinix.com/developers/api/metal/"),
            ("upcloud-password-v1", "UpCloud API password", "upcloud", "UPCLOUD_PASSWORD",
             r"upcloud[_-]?(?:api[_-]?)?password", "https://developers.upcloud.com/1.3/"),
            ("leaseweb-api-key-v1", "Leaseweb API key", "leaseweb", "LEASEWEB_KEY",
             r"leaseweb[_-]?(?:api[_-]?)?key", "https://developer.leaseweb.com/"),
            ("contabo-client-secret-v1", "Contabo client secret", "contabo", "CONTABO_SECRET",
             r"contabo[_-]?(?:client[_-]?)?secret", "https://api.contabo.com/"),
            # DNS / domains
            ("dnsimple-token-v1", "DNSimple API token", "dnsimple", "DNSIMPLE_TOKEN",
             r"dnsimple[_-]?(?:api[_-]?)?token", "https://developer.dnsimple.com/v2/#authentication"),
            ("desec-token-v1", "deSEC API token", "desec", "DESEC_TOKEN",
             r"desec[_-]?(?:api[_-]?)?token", "https://desec.readthedocs.io/en/latest/quickstart.html"),
            ("dnsmadeeasy-api-key-v1", "DNS Made Easy API key", "dnsmadeeasy", "DNSMADEEASY_KEY",
             r"dnsmadeeasy[_-]?(?:api[_-]?)?key", "https://api-docs.dnsmadeeasy.com/"),
            ("namecom-token-v1", "Name.com API token", "namecom", "NAMECOM_TOKEN",
             r"namecom[_-]?(?:api[_-]?)?token", "https://www.name.com/api-docs"),
            ("godaddy-api-secret-v1", "GoDaddy API secret", "godaddy", "GODADDY_SECRET",
             r"godaddy[_-]?(?:api[_-]?)?secret", "https://developer.godaddy.com/getstarted"),
            # transactional email
            ("smtp2go-api-key-v1", "SMTP2GO API key", "smtp2go", "SMTP2GO_KEY",
             r"smtp2go[_-]?(?:api[_-]?)?key", "https://apidoc.smtp2go.com/"),
            ("elasticemail-api-key-v1", "Elastic Email API key", "elasticemail", "ELASTICEMAIL_KEY",
             r"elasticemail[_-]?(?:api[_-]?)?key", "https://elasticemail.com/developers/api-documentation"),
            ("socketlabs-api-key-v1", "SocketLabs API key", "socketlabs", "SOCKETLABS_KEY",
             r"socketlabs[_-]?(?:api[_-]?)?key", "https://www.socketlabs.com/api-reference/"),
            ("mailtrap-api-token-v1", "Mailtrap API token", "mailtrap", "MAILTRAP_TOKEN",
             r"mailtrap[_-]?(?:api[_-]?)?token", "https://api-docs.mailtrap.io/"),
            ("mailersend-api-key-v1", "MailerSend API key", "mailersend", "MAILERSEND_KEY",
             r"mailersend[_-]?(?:api[_-]?)?key", "https://developers.mailersend.com/general.html#authentication"),
            # monitoring / uptime
            ("cronitor-api-key-v1", "Cronitor API key", "cronitor", "CRONITOR_KEY",
             r"cronitor[_-]?(?:api[_-]?)?key", "https://cronitor.io/docs/api"),
            ("healthchecks-api-key-v1", "Healthchecks.io API key", "healthchecks", "HEALTHCHECKS_KEY",
             r"healthchecks[_-]?(?:io[_-]?)?(?:api[_-]?)?key", "https://healthchecks.io/docs/api/"),
            ("statuscake-api-key-v1", "StatusCake API key", "statuscake", "STATUSCAKE_KEY",
             r"statuscake[_-]?(?:api[_-]?)?(?:key|token)", "https://www.statuscake.com/api/"),
            ("updown-api-key-v1", "Updown.io API key", "updown", "UPDOWN_KEY",
             r"updown[_-]?(?:io[_-]?)?(?:api[_-]?)?key", "https://updown.io/api"),
            # notifications / analytics
            ("june-api-key-v1", "June API key", "june", "JUNE_KEY",
             r"june[_-]?(?:api[_-]?)?key", "https://www.june.so/docs"),
            ("bento-api-key-v1", "Bento API key", "bento", "BENTO_KEY",
             r"bento[_-]?(?:api[_-]?)?key", "https://docs.bentonow.com/"),
            ("knock-api-key-v1", "Knock API key", "knock", "KNOCK_KEY",
             r"knock[_-]?(?:api[_-]?)?(?:key|secret)", "https://docs.knock.app/developer-tools/api-keys"),
            ("novu-api-key-v1", "Novu API key", "novu", "NOVU_KEY",
             r"novu[_-]?(?:api[_-]?)?key", "https://docs.novu.co/api-reference/overview"),
            ("magicbell-api-secret-v1", "MagicBell API secret", "magicbell", "MAGICBELL_SECRET",
             r"magicbell[_-]?(?:api[_-]?)?secret", "https://www.magicbell.com/docs/rest-api/overview"),
            # payment / fintech
            ("helcim-api-token-v1", "Helcim API token", "helcim", "HELCIM_TOKEN",
             r"helcim[_-]?(?:api[_-]?)?token", "https://devdocs.helcim.com/docs/api-access-tokens"),
            ("clover-api-token-v1", "Clover API token", "clover", "CLOVER_TOKEN",
             r"clover[_-]?(?:api[_-]?)?token", "https://docs.clover.com/docs/using-oauth-20"),
            ("spreedly-access-secret-v1", "Spreedly access secret", "spreedly", "SPREEDLY_SECRET",
             r"spreedly[_-]?(?:access[_-]?)?secret", "https://docs.spreedly.com/guides/account/#api-credentials"),
            ("basistheory-api-key-v1", "Basis Theory API key", "basistheory", "BASISTHEORY_KEY",
             r"basistheory[_-]?(?:api[_-]?)?key", "https://developers.basistheory.com/docs/api/authentication"),
            ("vgs-api-key-v1", "VGS API key", "vgs", "VGS_KEY",
             r"vgs[_-]?(?:api[_-]?)?key", "https://www.verygoodsecurity.com/docs/"),
            # auth / identity / MFA
            ("onelogin-client-secret-v1", "OneLogin client secret", "onelogin", "ONELOGIN_SECRET",
             r"onelogin[_-]?(?:client[_-]?)?secret", "https://developers.onelogin.com/api-docs/2/getting-started/dev-overview"),
            ("jumpcloud-api-key-v1", "JumpCloud API key", "jumpcloud", "JUMPCLOUD_KEY",
             r"jumpcloud[_-]?(?:api[_-]?)?key", "https://docs.jumpcloud.com/api/"),
            ("duo-secret-key-v1", "Duo secret key", "duo", "DUO_SECRET_KEY",
             r"duo[_-]?(?:integration[_-]?|secret[_-]?)?key", "https://duo.com/docs/adminapi"),
            ("yubico-api-secret-v1", "Yubico API secret", "yubico", "YUBICO_SECRET",
             r"yubico[_-]?(?:api[_-]?)?secret", "https://developers.yubico.com/API_Client_Libraries/"),
            ("authy-api-key-v1", "Authy API key", "authy", "AUTHY_KEY",
             r"authy[_-]?(?:api[_-]?)?key", "https://www.twilio.com/docs/verify/api"),
        ]),

        # ---- twenty-eighth batch: design / docs / forms / HR / accounting / CDP ----
        *_labelled_batch([
            # design / creative
            ("canva-api-key-v1", "Canva API key", "canva", "CANVA_KEY",
             r"canva[_-]?(?:api[_-]?)?key", "https://www.canva.dev/docs/connect/authentication/"),
            ("adobe-client-secret-v1", "Adobe client secret", "adobe", "ADOBE_SECRET",
             r"adobe[_-]?(?:client[_-]?)?secret", "https://developer.adobe.com/developer-console/docs/guides/authentication/"),
            ("framer-api-token-v1", "Framer API token", "framer", "FRAMER_TOKEN",
             r"framer[_-]?(?:api[_-]?)?token", "https://www.framer.com/developers/"),
            ("zeplin-access-token-v1", "Zeplin access token", "zeplin", "ZEPLIN_TOKEN",
             r"zeplin[_-]?(?:personal[_-]?)?(?:access[_-]?)?token", "https://docs.zeplin.dev/docs/getting-started"),
            ("dribbble-client-secret-v1", "Dribbble client secret", "dribbble", "DRIBBBLE_SECRET",
             r"dribbble[_-]?(?:client[_-]?)?secret", "https://developer.dribbble.com/v2/oauth/"),
            # docs / knowledge
            ("gitbook-api-token-v1", "GitBook API token", "gitbook", "GITBOOK_TOKEN",
             r"gitbook[_-]?(?:api[_-]?)?token", "https://developer.gitbook.com/gitbook-api/authentication"),
            ("readthedocs-token-v1", "Read the Docs API token", "readthedocs", "READTHEDOCS_TOKEN",
             r"readthedocs[_-]?(?:api[_-]?)?token", "https://docs.readthedocs.io/en/stable/api/v3.html"),
            # forms / surveys
            ("jotform-api-key-v1", "Jotform API key", "jotform", "JOTFORM_KEY",
             r"jotform[_-]?(?:api[_-]?)?key", "https://api.jotform.com/docs/"),
            ("surveymonkey-token-v1", "SurveyMonkey access token", "surveymonkey", "SURVEYMONKEY_TOKEN",
             r"surveymonkey[_-]?(?:access[_-]?)?token", "https://api.surveymonkey.com/v3/docs"),
            ("qualtrics-api-token-v1", "Qualtrics API token", "qualtrics", "QUALTRICS_TOKEN",
             r"qualtrics[_-]?(?:api[_-]?)?token", "https://api.qualtrics.com/"),
            ("tally-api-key-v1", "Tally API key", "tally", "TALLY_KEY",
             r"tally[_-]?(?:api[_-]?)?key", "https://developers.tally.so/"),
            ("formstack-token-v1", "Formstack API token", "formstack", "FORMSTACK_TOKEN",
             r"formstack[_-]?(?:api[_-]?)?token", "https://developers.formstack.com/docs/oauth"),
            ("wufoo-api-key-v1", "Wufoo API key", "wufoo", "WUFOO_KEY",
             r"wufoo[_-]?(?:api[_-]?)?key", "https://help.wufoo.com/articles/en_US/kb/API"),
            # HR / recruiting / payroll
            ("gusto-api-token-v1", "Gusto API token", "gusto", "GUSTO_TOKEN",
             r"gusto[_-]?(?:api[_-]?)?token", "https://docs.gusto.com/app-integrations/docs/authentication"),
            ("rippling-api-key-v1", "Rippling API key", "rippling", "RIPPLING_KEY",
             r"rippling[_-]?(?:api[_-]?)?key", "https://developer.rippling.com/documentation/rest-api/"),
            ("bamboohr-api-key-v1", "BambooHR API key", "bamboohr", "BAMBOOHR_KEY",
             r"bamboohr[_-]?(?:api[_-]?)?key", "https://documentation.bamboohr.com/docs/getting-started"),
            ("deel-api-token-v1", "Deel API token", "deel", "DEEL_TOKEN",
             r"deel[_-]?(?:api[_-]?)?token", "https://developer.deel.com/docs/api-tokens"),
            ("greenhouse-api-key-v1", "Greenhouse API key", "greenhouse", "GREENHOUSE_KEY",
             r"greenhouse[_-]?(?:harvest[_-]?)?(?:api[_-]?)?key", "https://developers.greenhouse.io/harvest.html"),
            ("lever-api-key-v1", "Lever API key", "lever", "LEVER_KEY",
             r"lever[_-]?(?:api[_-]?)?key", "https://hire.lever.co/developer/documentation"),
            ("ashby-api-key-v1", "Ashby API key", "ashby", "ASHBY_KEY",
             r"ashby[_-]?(?:api[_-]?)?key", "https://developers.ashbyhq.com/"),
            ("workable-api-key-v1", "Workable API key", "workable", "WORKABLE_KEY",
             r"workable[_-]?(?:api[_-]?)?(?:key|token)", "https://workable.readme.io/reference/generate-an-access-token"),
            # accounting / finance ops
            ("quickbooks-client-secret-v1", "QuickBooks client secret", "quickbooks", "QUICKBOOKS_SECRET",
             r"quickbooks[_-]?(?:client[_-]?)?secret", "https://developer.intuit.com/app/developer/qbo/docs/develop/authentication-and-authorization"),
            ("xero-client-secret-v1", "Xero client secret", "xero", "XERO_SECRET",
             r"xero[_-]?(?:client[_-]?)?secret", "https://developer.xero.com/documentation/guides/oauth2/auth-flow/"),
            ("freshbooks-client-secret-v1", "FreshBooks client secret", "freshbooks", "FRESHBOOKS_SECRET",
             r"freshbooks[_-]?(?:client[_-]?)?secret", "https://www.freshbooks.com/api/start"),
            ("sage-api-key-v1", "Sage API key", "sage", "SAGE_KEY",
             r"sage[_-]?(?:api[_-]?)?(?:key|secret)", "https://developer.sage.com/"),
            ("billcom-dev-key-v1", "Bill.com developer key", "billcom", "BILLCOM_KEY",
             r"billcom[_-]?(?:dev[_-]?)?key", "https://developer.bill.com/docs/authentication"),
            ("expensify-partner-secret-v1", "Expensify partner secret", "expensify", "EXPENSIFY_SECRET",
             r"expensify[_-]?(?:partner[_-]?)?(?:user[_-]?)?secret", "https://integrations.expensify.com/Integration-Server/doc/"),
            # CDP / analytics
            ("mparticle-api-secret-v1", "mParticle API secret", "mparticle", "MPARTICLE_SECRET",
             r"mparticle[_-]?(?:api[_-]?)?secret", "https://docs.mparticle.com/developers/apis/authentication/"),
            ("jitsu-server-secret-v1", "Jitsu server secret", "jitsu", "JITSU_SECRET",
             r"jitsu[_-]?(?:server[_-]?)?secret", "https://docs.jitsu.com/"),
            # conferencing / video
            ("whereby-api-key-v1", "Whereby API key", "whereby", "WHEREBY_KEY",
             r"whereby[_-]?(?:api[_-]?)?key", "https://docs.whereby.com/reference/authentication"),
            ("dyte-api-key-v1", "Dyte API key", "dyte", "DYTE_KEY",
             r"dyte[_-]?(?:api[_-]?)?key", "https://docs.dyte.io/api"),
        ]),

        # ---- twenty-ninth batch: observability / storage / vector / fintech / ads / intel ----
        *_labelled_batch([
            # observability / logs
            ("lightstep-token-v1", "Lightstep access token", "lightstep", "LIGHTSTEP_TOKEN",
             r"lightstep[_-]?(?:access[_-]?)?token", "https://docs.lightstep.com/docs/create-and-manage-access-tokens"),
            ("zabbix-api-token-v1", "Zabbix API token", "zabbix", "ZABBIX_TOKEN",
             r"zabbix[_-]?(?:api[_-]?)?token", "https://www.zabbix.com/documentation/current/en/manual/api"),
            ("sematext-api-key-v1", "Sematext API key", "sematext", "SEMATEXT_KEY",
             r"sematext[_-]?(?:api[_-]?)?key", "https://sematext.com/docs/"),
            ("graylog-api-token-v1", "Graylog API token", "graylog", "GRAYLOG_TOKEN",
             r"graylog[_-]?(?:api[_-]?)?token", "https://docs.graylog.org/docs/rest-api"),
            ("humio-ingest-token-v1", "Humio (LogScale) ingest token", "humio", "HUMIO_TOKEN",
             r"humio[_-]?(?:ingest[_-]?)?token", "https://library.humio.com/data-analysis/api-ingest.html"),
            ("devo-api-key-v1", "Devo API key", "devo", "DEVO_KEY",
             r"devo[_-]?(?:api[_-]?)?key", "https://docs.devo.com/space/latest/api-reference"),
            # cloud storage
            ("backblaze-app-key-v1", "Backblaze B2 application key", "backblaze", "BACKBLAZE_KEY",
             r"backblaze[_-]?(?:b2[_-]?)?(?:application[_-]?)?key", "https://www.backblaze.com/docs/cloud-storage-application-keys"),
            ("wasabi-secret-key-v1", "Wasabi secret key", "wasabi", "WASABI_SECRET_KEY",
             r"wasabi[_-]?(?:access[_-]?|secret[_-]?)?key", "https://docs.wasabi.com/docs/creating-a-subuser-access-key"),
            ("storj-api-key-v1", "Storj API key", "storj", "STORJ_KEY",
             r"storj[_-]?(?:api[_-]?)?key", "https://docs.storj.io/dcs/access"),
            ("minio-secret-key-v1", "MinIO secret key", "minio", "MINIO_SECRET_KEY",
             r"minio[_-]?(?:access[_-]?|secret[_-]?)?key", "https://min.io/docs/minio/linux/administration/identity-access-management.html"),
            # vector / ML infra
            ("milvus-token-v1", "Milvus/Zilliz token", "milvus", "MILVUS_TOKEN",
             r"milvus[_-]?token", "https://milvus.io/docs/authenticate.md"),
            ("zilliz-api-key-v1", "Zilliz Cloud API key", "zilliz", "ZILLIZ_KEY",
             r"zilliz[_-]?(?:api[_-]?)?key", "https://docs.zilliz.com/docs/manage-api-keys"),
            ("chroma-token-v1", "Chroma auth token", "chroma", "CHROMA_TOKEN",
             r"chroma[_-]?(?:auth[_-]?|api[_-]?)?token", "https://docs.trychroma.com/production/administration/auth"),
            ("marqo-api-key-v1", "Marqo API key", "marqo", "MARQO_KEY",
             r"marqo[_-]?(?:api[_-]?)?key", "https://docs.marqo.ai/"),
            # ETL / data platform
            ("stitch-api-token-v1", "Stitch Data API token", "stitch", "STITCH_TOKEN",
             r"stitch[_-]?(?:data[_-]?)?(?:api[_-]?)?token", "https://www.stitchdata.com/docs/developers/import-api/guides/basic-usage"),
            ("astronomer-api-token-v1", "Astronomer API token", "astronomer", "ASTRONOMER_TOKEN",
             r"astronomer[_-]?(?:api[_-]?)?token", "https://www.astronomer.io/docs/astro/automation-authentication"),
            # fintech / crypto infra
            ("circle-api-key-v1", "Circle API key", "circle", "CIRCLE_API_KEY",
             r"circle[_-]?(?:api[_-]?)?key", "https://developers.circle.com/circle-mint/docs/api-keys"),
            ("fireblocks-api-secret-v1", "Fireblocks API secret", "fireblocks", "FIREBLOCKS_SECRET",
             r"fireblocks[_-]?(?:api[_-]?)?(?:key|secret)", "https://developers.fireblocks.com/docs/quickstart"),
            ("bitgo-access-token-v1", "BitGo access token", "bitgo", "BITGO_TOKEN",
             r"bitgo[_-]?(?:access[_-]?)?token", "https://developers.bitgo.com/guides/get-started/tokens"),
            ("web3auth-secret-v1", "Web3Auth client secret", "web3auth", "WEB3AUTH_SECRET",
             r"web3auth[_-]?(?:client[_-]?)?secret", "https://web3auth.io/docs/"),
            ("crossmint-server-key-v1", "Crossmint server key", "crossmint", "CROSSMINT_KEY",
             r"crossmint[_-]?(?:api[_-]?|server[_-]?)?key", "https://docs.crossmint.com/introduction/platform/api-keys"),
            ("privy-app-secret-v1", "Privy app secret", "privy", "PRIVY_SECRET",
             r"privy[_-]?(?:app[_-]?)?secret", "https://docs.privy.io/guide/server/setup/api-keys"),
            # advertising
            ("taboola-client-secret-v1", "Taboola client secret", "taboola", "TABOOLA_SECRET",
             r"taboola[_-]?(?:client[_-]?)?secret", "https://developers.taboola.com/backstage-api/reference/welcome"),
            ("outbrain-token-v1", "Outbrain API token", "outbrain", "OUTBRAIN_TOKEN",
             r"outbrain[_-]?(?:api[_-]?)?(?:key|token)", "https://amplifyv01.docs.apiary.io/"),
            ("bingads-developer-token-v1", "Microsoft (Bing) Ads developer token", "bingads", "BINGADS_TOKEN",
             r"bingads[_-]?(?:developer[_-]?)?token", "https://learn.microsoft.com/en-us/advertising/guides/get-started"),
            # security intel
            ("shodan-api-key-v1", "Shodan API key", "shodan", "SHODAN_KEY",
             r"shodan[_-]?(?:api[_-]?)?key", "https://developer.shodan.io/api"),
            ("censys-api-secret-v1", "Censys API secret", "censys", "CENSYS_SECRET",
             r"censys[_-]?(?:api[_-]?)?(?:id|secret)", "https://search.censys.io/api"),
            ("virustotal-api-key-v1", "VirusTotal API key", "virustotal", "VIRUSTOTAL_KEY",
             r"virustotal[_-]?(?:api[_-]?)?key", "https://docs.virustotal.com/reference/authentication"),
            ("abuseipdb-api-key-v1", "AbuseIPDB API key", "abuseipdb", "ABUSEIPDB_KEY",
             r"abuseipdb[_-]?(?:api[_-]?)?key", "https://docs.abuseipdb.com/"),
            ("greynoise-api-key-v1", "GreyNoise API key", "greynoise", "GREYNOISE_KEY",
             r"greynoise[_-]?(?:api[_-]?)?key", "https://docs.greynoise.io/docs/using-the-greynoise-api"),
            ("securitytrails-api-key-v1", "SecurityTrails API key", "securitytrails", "SECURITYTRAILS_KEY",
             r"securitytrails[_-]?(?:api[_-]?)?key", "https://docs.securitytrails.com/docs"),
            ("ipinfo-token-v1", "IPinfo access token", "ipinfo", "IPINFO_TOKEN",
             r"ipinfo[_-]?(?:api[_-]?|access[_-]?)?token", "https://ipinfo.io/developers"),
            ("maxmind-license-key-v1", "MaxMind license key", "maxmind", "MAXMIND_LICENSE_KEY",
             r"maxmind[_-]?(?:license[_-]?)?key", "https://dev.maxmind.com/geoip/docs/web-services"),
            ("urlscan-api-key-v1", "urlscan.io API key", "urlscan", "URLSCAN_KEY",
             r"urlscan[_-]?(?:io[_-]?)?(?:api[_-]?)?key", "https://urlscan.io/docs/api/"),
        ]),

        # ---- thirtieth batch: i18n / weather / PDF / scraping / OCR / data infra ----
        *_labelled_batch([
            # translation / localization
            ("deepl-api-key-v1", "DeepL API key", "deepl", "DEEPL_KEY",
             r"deepl[_-]?(?:api[_-]?)?key", "https://developers.deepl.com/docs/getting-started/auth"),
            ("lokalise-api-token-v1", "Lokalise API token", "lokalise", "LOKALISE_TOKEN",
             r"lokalise[_-]?(?:api[_-]?)?token", "https://developers.lokalise.com/reference/api-authentication"),
            ("crowdin-api-token-v1", "Crowdin API token", "crowdin", "CROWDIN_TOKEN",
             r"crowdin[_-]?(?:api[_-]?|personal[_-]?)?token", "https://support.crowdin.com/developer/api/v2/"),
            ("phrase-api-token-v1", "Phrase API token", "phrase", "PHRASE_TOKEN",
             r"phrase[_-]?(?:app[_-]?)?(?:api[_-]?)?token", "https://developers.phrase.com/api/"),
            ("transifex-api-token-v1", "Transifex API token", "transifex", "TRANSIFEX_TOKEN",
             r"transifex[_-]?(?:api[_-]?)?token", "https://developers.transifex.com/reference/api-authentication"),
            ("weblate-api-key-v1", "Weblate API key", "weblate", "WEBLATE_KEY",
             r"weblate[_-]?(?:api[_-]?)?key", "https://docs.weblate.org/en/latest/api.html"),
            ("poeditor-api-token-v1", "POEditor API token", "poeditor", "POEDITOR_TOKEN",
             r"poeditor[_-]?(?:api[_-]?)?token", "https://poeditor.com/docs/api"),
            # weather
            ("weatherapi-key-v1", "WeatherAPI.com key", "weatherapi", "WEATHERAPI_KEY",
             r"weatherapi[_-]?(?:com[_-]?)?key", "https://www.weatherapi.com/docs/"),
            ("tomorrowio-api-key-v1", "Tomorrow.io API key", "tomorrowio", "TOMORROWIO_KEY",
             r"tomorrowio[_-]?(?:api[_-]?)?key", "https://docs.tomorrow.io/reference/intro/authentication"),
            ("weatherbit-api-key-v1", "Weatherbit API key", "weatherbit", "WEATHERBIT_KEY",
             r"weatherbit[_-]?(?:api[_-]?)?key", "https://www.weatherbit.io/api"),
            # PDF / document processing
            ("pdfmonkey-api-key-v1", "PDFMonkey API key", "pdfmonkey", "PDFMONKEY_KEY",
             r"pdfmonkey[_-]?(?:api[_-]?)?key", "https://docs.pdfmonkey.io/references/api/authentication"),
            ("pdfshift-api-key-v1", "PDFShift API key", "pdfshift", "PDFSHIFT_KEY",
             r"pdfshift[_-]?(?:api[_-]?)?key", "https://docs.pdfshift.io/"),
            ("cloudconvert-api-key-v1", "CloudConvert API key", "cloudconvert", "CLOUDCONVERT_KEY",
             r"cloudconvert[_-]?(?:api[_-]?)?key", "https://cloudconvert.com/api/v2"),
            ("api2pdf-api-key-v1", "Api2Pdf API key", "api2pdf", "API2PDF_KEY",
             r"api2pdf[_-]?(?:api[_-]?)?key", "https://www.api2pdf.com/documentation/"),
            # scraping / proxy
            ("scraperapi-key-v1", "ScraperAPI key", "scraperapi", "SCRAPERAPI_KEY",
             r"scraperapi[_-]?(?:api[_-]?)?key", "https://docs.scraperapi.com/"),
            ("scrapingbee-api-key-v1", "ScrapingBee API key", "scrapingbee", "SCRAPINGBEE_KEY",
             r"scrapingbee[_-]?(?:api[_-]?)?key", "https://www.scrapingbee.com/documentation/"),
            ("brightdata-api-token-v1", "Bright Data API token", "brightdata", "BRIGHTDATA_TOKEN",
             r"brightdata[_-]?(?:api[_-]?)?(?:token|key)", "https://docs.brightdata.com/api-reference/authentication"),
            ("zyte-api-key-v1", "Zyte API key", "zyte", "ZYTE_KEY",
             r"zyte[_-]?(?:api[_-]?)?key", "https://docs.zyte.com/zyte-api/get-started.html"),
            ("apify-api-token-v1", "Apify API token", "apify", "APIFY_TOKEN",
             r"apify[_-]?(?:api[_-]?)?token", "https://docs.apify.com/api/v2#/introduction/authentication"),
            ("serpapi-key-v1", "SerpApi key", "serpapi", "SERPAPI_KEY",
             r"serpapi[_-]?(?:api[_-]?)?key", "https://serpapi.com/search-api"),
            ("serper-api-key-v1", "Serper API key", "serper", "SERPER_KEY",
             r"serper[_-]?(?:api[_-]?)?key", "https://serper.dev/"),
            ("firecrawl-api-key-v1", "Firecrawl API key", "firecrawl", "FIRECRAWL_KEY",
             r"firecrawl[_-]?(?:api[_-]?)?key", "https://docs.firecrawl.dev/introduction"),
            ("diffbot-token-v1", "Diffbot token", "diffbot", "DIFFBOT_TOKEN",
             r"diffbot[_-]?(?:api[_-]?)?token", "https://docs.diffbot.com/reference/authentication"),
            ("browserless-token-v1", "Browserless token", "browserless", "BROWSERLESS_TOKEN",
             r"browserless[_-]?(?:api[_-]?)?(?:token|key)", "https://docs.browserless.io/"),
            ("scrapfly-api-key-v1", "Scrapfly API key", "scrapfly", "SCRAPFLY_KEY",
             r"scrapfly[_-]?(?:api[_-]?)?key", "https://scrapfly.io/docs/scrape-api/getting-started"),
            # OCR / document AI
            ("mindee-api-key-v1", "Mindee API key", "mindee", "MINDEE_KEY",
             r"mindee[_-]?(?:api[_-]?)?key", "https://developers.mindee.com/docs/authentication"),
            ("nanonets-api-key-v1", "Nanonets API key", "nanonets", "NANONETS_KEY",
             r"nanonets[_-]?(?:api[_-]?)?key", "https://nanonets.com/documentation/"),
            ("veryfi-client-secret-v1", "Veryfi client secret", "veryfi", "VERYFI_SECRET",
             r"veryfi[_-]?(?:client[_-]?)?secret", "https://docs.veryfi.com/api/"),
            # phone validation
            ("numverify-api-key-v1", "Numverify API key", "numverify", "NUMVERIFY_KEY",
             r"numverify[_-]?(?:api[_-]?)?key", "https://numverify.com/documentation"),
            # data infra
            ("tinybird-token-v1", "Tinybird token", "tinybird", "TINYBIRD_TOKEN",
             r"tinybird[_-]?(?:api[_-]?|admin[_-]?)?token", "https://www.tinybird.co/docs/api-reference/token-api"),
            ("motherduck-token-v1", "MotherDuck token", "motherduck", "MOTHERDUCK_TOKEN",
             r"motherduck[_-]?token", "https://motherduck.com/docs/key-tasks/authenticating-to-motherduck/"),
            ("sqlitecloud-api-key-v1", "SQLite Cloud API key", "sqlitecloud", "SQLITECLOUD_KEY",
             r"sqlitecloud[_-]?(?:api[_-]?)?key", "https://docs.sqlitecloud.io/docs/introduction"),
            ("valtown-api-token-v1", "Val Town API token", "valtown", "VALTOWN_TOKEN",
             r"valtown[_-]?(?:api[_-]?)?token", "https://docs.val.town/api/"),
            ("zeabur-api-token-v1", "Zeabur API token", "zeabur", "ZEABUR_TOKEN",
             r"zeabur[_-]?(?:api[_-]?)?token", "https://zeabur.com/docs/developer/public-api"),
        ]),

        # ---- thirty-first batch: LLM-ops / AI gateways + CRM / email / phone ----
        *_labelled_batch([
            # AI models / media
            ("alephalpha-api-token-v1", "Aleph Alpha API token", "alephalpha", "ALEPHALPHA_TOKEN",
             r"alephalpha[_-]?(?:api[_-]?)?token", "https://docs.aleph-alpha.com/"),
            ("leonardo-api-key-v1", "Leonardo.Ai API key", "leonardo", "LEONARDO_KEY",
             r"leonardo[_-]?(?:ai[_-]?)?(?:api[_-]?)?key", "https://docs.leonardo.ai/docs/getting-started"),
            ("recraft-api-token-v1", "Recraft API token", "recraft", "RECRAFT_TOKEN",
             r"recraft[_-]?(?:api[_-]?)?token", "https://www.recraft.ai/docs"),
            ("ideogram-api-key-v1", "Ideogram API key", "ideogram", "IDEOGRAM_KEY",
             r"ideogram[_-]?(?:api[_-]?)?key", "https://developer.ideogram.ai/"),
            ("playht-api-key-v1", "PlayHT API key", "playht", "PLAYHT_KEY",
             r"playht[_-]?(?:api[_-]?)?key", "https://docs.play.ht/reference/api-authentication"),
            ("lmnt-api-key-v1", "LMNT API key", "lmnt", "LMNT_KEY",
             r"lmnt[_-]?(?:api[_-]?)?key", "https://docs.lmnt.com/"),
            ("cartesia-api-key-v1", "Cartesia API key", "cartesia", "CARTESIA_KEY",
             r"cartesia[_-]?(?:api[_-]?)?key", "https://docs.cartesia.ai/"),
            ("rime-api-key-v1", "Rime API key", "rime", "RIME_KEY",
             r"rime[_-]?(?:api[_-]?)?key", "https://docs.rime.ai/"),
            ("hume-api-key-v1", "Hume AI API key", "hume", "HUME_KEY",
             r"hume[_-]?(?:ai[_-]?)?(?:api[_-]?)?key", "https://dev.hume.ai/docs/introduction/api-key"),
            ("tavily-api-key-v1", "Tavily API key", "tavily", "TAVILY_KEY",
             r"tavily[_-]?(?:api[_-]?)?key", "https://docs.tavily.com/"),
            ("youcom-api-key-v1", "You.com API key", "youcom", "YOUCOM_KEY",
             r"youcom[_-]?(?:api[_-]?)?key", "https://documentation.you.com/"),
            ("mixedbread-api-key-v1", "Mixedbread API key", "mixedbread", "MIXEDBREAD_KEY",
             r"mixedbread[_-]?(?:api[_-]?)?key", "https://www.mixedbread.com/api-reference"),
            ("forefront-api-key-v1", "Forefront API key", "forefront", "FOREFRONT_KEY",
             r"forefront[_-]?(?:api[_-]?)?key", "https://docs.forefront.ai/"),
            # LLM observability / gateways
            ("langfuse-secret-key-v1", "Langfuse secret key", "langfuse", "LANGFUSE_SECRET_KEY",
             r"langfuse[_-]?(?:public[_-]?|secret[_-]?)?key", "https://langfuse.com/docs/api"),
            ("helicone-api-key-v1", "Helicone API key", "helicone", "HELICONE_KEY",
             r"helicone[_-]?(?:api[_-]?)?key", "https://docs.helicone.ai/getting-started/quick-start"),
            ("portkey-api-key-v1", "Portkey API key", "portkey", "PORTKEY_KEY",
             r"portkey[_-]?(?:api[_-]?)?key", "https://portkey.ai/docs/api-reference/authentication"),
            ("braintrust-api-key-v1", "Braintrust API key", "braintrust", "BRAINTRUST_KEY",
             r"braintrust[_-]?(?:api[_-]?)?key", "https://www.braintrust.dev/docs/reference/api"),
            ("humanloop-api-key-v1", "Humanloop API key", "humanloop", "HUMANLOOP_KEY",
             r"humanloop[_-]?(?:api[_-]?)?key", "https://humanloop.com/docs/v5/api-reference/sdks"),
            ("literalai-api-key-v1", "Literal AI API key", "literalai", "LITERALAI_KEY",
             r"literalai[_-]?(?:api[_-]?)?key", "https://docs.literalai.com/"),
            ("promptlayer-api-key-v1", "PromptLayer API key", "promptlayer", "PROMPTLAYER_KEY",
             r"promptlayer[_-]?(?:api[_-]?)?key", "https://docs.promptlayer.com/"),
            ("vellum-api-key-v1", "Vellum API key", "vellum", "VELLUM_KEY",
             r"vellum[_-]?(?:api[_-]?)?key", "https://docs.vellum.ai/api-reference/introduction/getting-started"),
            ("arize-api-key-v1", "Arize API key", "arize", "ARIZE_KEY",
             r"arize[_-]?(?:api[_-]?|space[_-]?)?key", "https://docs.arize.com/arize/api-reference"),
            ("whylabs-api-key-v1", "WhyLabs API key", "whylabs", "WHYLABS_KEY",
             r"whylabs[_-]?(?:api[_-]?)?key", "https://docs.whylabs.ai/docs/"),
            # CRM / sales
            ("freshsales-api-key-v1", "Freshsales API key", "freshsales", "FRESHSALES_KEY",
             r"freshsales[_-]?(?:api[_-]?)?key", "https://developers.freshworks.com/crm/api/"),
            ("insightly-api-key-v1", "Insightly API key", "insightly", "INSIGHTLY_KEY",
             r"insightly[_-]?(?:api[_-]?)?key", "https://api.insightly.com/v3.1/Help"),
            ("nutshell-api-key-v1", "Nutshell API key", "nutshell", "NUTSHELL_KEY",
             r"nutshell[_-]?(?:api[_-]?)?key", "https://developers.nutshell.com/"),
            ("keap-api-key-v1", "Keap API key", "keap", "KEAP_KEY",
             r"keap[_-]?(?:api[_-]?)?key", "https://developer.keap.com/docs/rest/"),
            # email marketing
            ("sendpulse-secret-v1", "SendPulse client secret", "sendpulse", "SENDPULSE_SECRET",
             r"sendpulse[_-]?(?:client[_-]?)?secret", "https://sendpulse.com/integrations/api"),
            ("moosend-api-key-v1", "Moosend API key", "moosend", "MOOSEND_KEY",
             r"moosend[_-]?(?:api[_-]?)?key", "https://docs.moosend.com/"),
            ("emailoctopus-api-key-v1", "EmailOctopus API key", "emailoctopus", "EMAILOCTOPUS_KEY",
             r"emailoctopus[_-]?(?:api[_-]?)?key", "https://emailoctopus.com/api-documentation"),
            # telephony
            ("ringcentral-client-secret-v1", "RingCentral client secret", "ringcentral", "RINGCENTRAL_SECRET",
             r"ringcentral[_-]?(?:client[_-]?)?secret", "https://developers.ringcentral.com/guide/authentication"),
            ("dialpad-api-token-v1", "Dialpad API token", "dialpad", "DIALPAD_TOKEN",
             r"dialpad[_-]?(?:api[_-]?)?token", "https://developers.dialpad.com/docs/authentication"),
            ("aircall-api-token-v1", "Aircall API token", "aircall", "AIRCALL_TOKEN",
             r"aircall[_-]?(?:api[_-]?)?(?:id|token)", "https://developer.aircall.io/api-references/"),
            ("openphone-api-key-v1", "OpenPhone API key", "openphone", "OPENPHONE_KEY",
             r"openphone[_-]?(?:api[_-]?)?key", "https://www.openphone.com/docs/mdx/api-reference/introduction"),
        ]),

        # ---- thirty-second batch: devops / messaging / on-call / commerce / tax / DB ----
        *_labelled_batch([
            # devops / platform
            ("teleport-api-token-v1", "Teleport API token", "teleport", "TELEPORT_TOKEN",
             r"teleport[_-]?(?:api[_-]?)?token", "https://goteleport.com/docs/reference/authentication/"),
            ("env0-api-key-v1", "env0 API key", "env0", "ENV0_KEY",
             r"env0[_-]?(?:api[_-]?)?key", "https://docs.env0.com/reference/authentication"),
            ("scalr-api-token-v1", "Scalr API token", "scalr", "SCALR_TOKEN",
             r"scalr[_-]?(?:api[_-]?)?token", "https://docs.scalr.io/docs/api"),
            ("portainer-api-token-v1", "Portainer API token", "portainer", "PORTAINER_TOKEN",
             r"portainer[_-]?(?:api[_-]?)?(?:key|token)", "https://docs.portainer.io/api/access"),
            ("rancher-api-token-v1", "Rancher API token", "rancher", "RANCHER_TOKEN",
             r"rancher[_-]?(?:api[_-]?|access[_-]?)?(?:key|token)", "https://ranchermanager.docs.rancher.com/api/quickstart"),
            ("argocd-auth-token-v1", "Argo CD auth token", "argocd", "ARGOCD_TOKEN",
             r"argocd[_-]?(?:auth[_-]?)?token", "https://argo-cd.readthedocs.io/en/stable/developer-guide/api-docs/"),
            ("concourse-api-token-v1", "Concourse CI token", "concourse", "CONCOURSE_TOKEN",
             r"concourse[_-]?(?:api[_-]?)?token", "https://concourse-ci.org/"),
            ("bamboo-api-token-v1", "Bamboo CI token", "bamboo", "BAMBOO_TOKEN",
             r"bamboo[_-]?(?:api[_-]?)?token", "https://developer.atlassian.com/server/bamboo/rest-apis/"),
            # messaging / streaming
            ("confluent-cloud-secret-v1", "Confluent Cloud API secret", "confluent", "CONFLUENT_SECRET",
             r"confluent[_-]?(?:cloud[_-]?)?(?:api[_-]?)?(?:key|secret)", "https://docs.confluent.io/cloud/current/access-management/authenticate/api-keys/api-keys.html"),
            ("redpanda-cloud-token-v1", "Redpanda Cloud token", "redpanda", "REDPANDA_TOKEN",
             r"redpanda[_-]?(?:cloud[_-]?)?(?:api[_-]?)?token", "https://docs.redpanda.com/redpanda-cloud/"),
            ("nats-token-v1", "NATS token", "nats", "NATS_TOKEN",
             r"nats[_-]?(?:auth[_-]?)?token", "https://docs.nats.io/running-a-nats-service/configuration/securing_nats/auth_intro/tokens"),
            # incident / on-call / status
            ("squadcast-api-token-v1", "Squadcast API token", "squadcast", "SQUADCAST_TOKEN",
             r"squadcast[_-]?(?:api[_-]?|refresh[_-]?)?token", "https://www.squadcast.com/developer-documentation"),
            ("rootly-api-key-v1", "Rootly API key", "rootly", "ROOTLY_KEY",
             r"rootly[_-]?(?:api[_-]?)?key", "https://docs.rootly.com/api-reference/overview"),
            ("incidentio-api-key-v1", "incident.io API key", "incidentio", "INCIDENTIO_KEY",
             r"incidentio[_-]?(?:api[_-]?)?key", "https://api-docs.incident.io/"),
            ("firehydrant-api-key-v1", "FireHydrant API key", "firehydrant", "FIREHYDRANT_KEY",
             r"firehydrant[_-]?(?:api[_-]?)?(?:key|token)", "https://developers.firehydrant.io/"),
            ("ilert-api-key-v1", "iLert API key", "ilert", "ILERT_KEY",
             r"ilert[_-]?(?:api[_-]?)?key", "https://api.ilert.com/api-docs/"),
            ("instatus-api-key-v1", "Instatus API key", "instatus", "INSTATUS_KEY",
             r"instatus[_-]?(?:api[_-]?)?key", "https://instatus.com/help/api"),
            # e-commerce
            ("wix-api-key-v1", "Wix API key", "wix", "WIX_KEY",
             r"wix[_-]?(?:api[_-]?)?key", "https://dev.wix.com/docs/rest/articles/getting-started/api-keys"),
            ("prestashop-webservice-key-v1", "PrestaShop webservice key", "prestashop", "PRESTASHOP_KEY",
             r"prestashop[_-]?(?:webservice[_-]?)?key", "https://devdocs.prestashop-project.org/8/webservice/"),
            ("magento-access-token-v1", "Magento access token", "magento", "MAGENTO_TOKEN",
             r"magento[_-]?(?:access[_-]?)?token", "https://developer.adobe.com/commerce/webapi/get-started/authentication/"),
            ("shopware-api-key-v1", "Shopware API key", "shopware", "SHOPWARE_KEY",
             r"shopware[_-]?(?:api[_-]?|access[_-]?)?key", "https://developer.shopware.com/docs/guides/integrations-api/"),
            ("vtex-app-token-v1", "VTEX app token", "vtex", "VTEX_TOKEN",
             r"vtex[_-]?(?:app[_-]?)?(?:key|token)", "https://developers.vtex.com/docs/guides/authentication"),
            # tax
            ("avalara-license-key-v1", "Avalara license key", "avalara", "AVALARA_KEY",
             r"avalara[_-]?(?:license[_-]?)?key", "https://developer.avalara.com/avatax/authentication-in-avatax/"),
            ("taxjar-api-token-v1", "TaxJar API token", "taxjar", "TAXJAR_TOKEN",
             r"taxjar[_-]?(?:api[_-]?)?(?:token|key)", "https://developers.taxjar.com/api/reference/"),
            ("quaderno-api-key-v1", "Quaderno API key", "quaderno", "QUADERNO_KEY",
             r"quaderno[_-]?(?:api[_-]?)?key", "https://developers.quaderno.io/api/"),
            # databases / warehouses
            ("modal-token-secret-v1", "Modal token secret", "modal", "MODAL_TOKEN_SECRET",
             r"modal[_-]?(?:token[_-]?)?secret", "https://modal.com/docs/guide/tokens"),
            ("clickhouse-cloud-secret-v1", "ClickHouse Cloud API secret", "clickhouse", "CLICKHOUSE_SECRET",
             r"clickhouse[_-]?(?:cloud[_-]?)?(?:api[_-]?)?(?:key|secret)", "https://clickhouse.com/docs/en/cloud/manage/openapi"),
            ("cockroach-cloud-secret-v1", "CockroachDB Cloud API secret", "cockroach", "COCKROACH_SECRET",
             r"cockroach[_-]?(?:db[_-]?|cloud[_-]?)?(?:api[_-]?)?(?:key|secret)", "https://www.cockroachlabs.com/docs/cockroachcloud/cloud-api"),
            ("yugabyte-api-key-v1", "YugabyteDB Aeon API key", "yugabyte", "YUGABYTE_KEY",
             r"yugabyte[_-]?(?:api[_-]?)?key", "https://api-docs.yugabyte.com/docs/managed-apis/"),
            ("singlestore-api-key-v1", "SingleStore API key", "singlestore", "SINGLESTORE_KEY",
             r"singlestore[_-]?(?:api[_-]?)?key", "https://docs.singlestore.com/cloud/reference/management-api/"),
            ("redislabs-api-key-v1", "Redis Cloud API key", "redislabs", "REDISLABS_KEY",
             r"redislabs[_-]?(?:api[_-]?)?(?:key|secret)", "https://redis.io/docs/latest/operate/rc/api/"),
            ("uptrends-api-key-v1", "Uptrends API key", "uptrends", "UPTRENDS_KEY",
             r"uptrends[_-]?(?:api[_-]?)?key", "https://www.uptrends.com/support/kb/api"),
            ("site24x7-token-v1", "Site24x7 OAuth token", "site24x7", "SITE24X7_TOKEN",
             r"site24x7[_-]?(?:api[_-]?|oauth[_-]?)?token", "https://www.site24x7.com/help/api/"),
            ("embrace-api-token-v1", "Embrace API token", "embrace", "EMBRACE_TOKEN",
             r"embrace[_-]?(?:api[_-]?)?token", "https://embrace.io/docs/"),
        ]),

        # ---- thirty-third batch: AI models / vector / dev tools / exchanges ----
        *_labelled_batch([
            # AI model providers
            ("reka-api-key-v1", "Reka AI API key", "reka", "REKA_KEY",
             r"reka[_-]?(?:api[_-]?)?key", "https://docs.reka.ai/"),
            ("moonshot-api-key-v1", "Moonshot AI (Kimi) API key", "moonshot", "MOONSHOT_KEY",
             r"moonshot[_-]?(?:api[_-]?)?key", "https://platform.moonshot.cn/docs"),
            ("zhipu-api-key-v1", "Zhipu AI (GLM) API key", "zhipu", "ZHIPU_KEY",
             r"zhipu[_-]?(?:ai[_-]?)?(?:api[_-]?)?key", "https://open.bigmodel.cn/dev/api"),
            ("minimax-api-key-v1", "MiniMax API key", "minimax", "MINIMAX_KEY",
             r"minimax[_-]?(?:api[_-]?)?key", "https://www.minimaxi.com/document"),
            ("dashscope-api-key-v1", "DashScope (Qwen) API key", "dashscope", "DASHSCOPE_KEY",
             r"dashscope[_-]?(?:api[_-]?)?key", "https://help.aliyun.com/zh/dashscope/"),
            ("upstage-api-key-v1", "Upstage API key", "upstage", "UPSTAGE_KEY",
             r"upstage[_-]?(?:api[_-]?)?key", "https://developers.upstage.ai/docs/getting-started/authentication"),
            ("clova-api-key-v1", "Naver CLOVA API key", "clova", "CLOVA_KEY",
             r"clova[_-]?(?:studio[_-]?)?(?:api[_-]?)?key", "https://api.ncloud-docs.com/docs/ai-naver-clovastudio"),
            ("nebius-api-key-v1", "Nebius AI API key", "nebius", "NEBIUS_KEY",
             r"nebius[_-]?(?:api[_-]?)?key", "https://docs.nebius.com/studio/inference/quickstart"),
            ("unstructured-api-key-v1", "Unstructured API key", "unstructured", "UNSTRUCTURED_KEY",
             r"unstructured[_-]?(?:api[_-]?)?key", "https://docs.unstructured.io/api-reference/api-services/overview"),
            # vector / embeddings
            ("turbopuffer-api-key-v1", "turbopuffer API key", "turbopuffer", "TURBOPUFFER_KEY",
             r"turbopuffer[_-]?(?:api[_-]?)?key", "https://turbopuffer.com/docs/auth"),
            ("lancedb-api-key-v1", "LanceDB Cloud API key", "lancedb", "LANCEDB_KEY",
             r"lancedb[_-]?(?:api[_-]?)?key", "https://docs.lancedb.com/"),
            ("activeloop-token-v1", "Activeloop token", "activeloop", "ACTIVELOOP_TOKEN",
             r"activeloop[_-]?(?:api[_-]?)?token", "https://docs.activeloop.ai/"),
            ("vectara-api-key-v1", "Vectara API key", "vectara", "VECTARA_KEY",
             r"vectara[_-]?(?:api[_-]?)?key", "https://docs.vectara.com/docs/api-reference/auth-apis/api-keys"),
            ("trieve-api-key-v1", "Trieve API key", "trieve", "TRIEVE_KEY",
             r"trieve[_-]?(?:api[_-]?)?key", "https://docs.trieve.ai/"),
            # dev tools / code intelligence
            ("codeium-api-key-v1", "Codeium API key", "codeium", "CODEIUM_KEY",
             r"codeium[_-]?(?:api[_-]?)?key", "https://codeium.com/"),
            ("tabnine-api-key-v1", "Tabnine API key", "tabnine", "TABNINE_KEY",
             r"tabnine[_-]?(?:api[_-]?)?key", "https://www.tabnine.com/"),
            ("greptile-api-key-v1", "Greptile API key", "greptile", "GREPTILE_KEY",
             r"greptile[_-]?(?:api[_-]?)?key", "https://docs.greptile.com/"),
            ("codacy-project-token-v1", "Codacy project token", "codacy", "CODACY_TOKEN",
             r"codacy[_-]?(?:api[_-]?|project[_-]?)?token", "https://docs.codacy.com/codacy-api/api-tokens/"),
            ("deepsource-dsn-v1", "DeepSource DSN", "deepsource", "DEEPSOURCE_DSN",
             r"deepsource[_-]?(?:api[_-]?)?(?:dsn|key)", "https://docs.deepsource.com/"),
            # A/B testing / hosting
            ("vwo-token-v1", "VWO API token", "vwo", "VWO_TOKEN",
             r"vwo[_-]?(?:api[_-]?|account[_-]?)?token", "https://developers.vwo.com/"),
            ("clevercloud-secret-v1", "Clever Cloud secret", "clevercloud", "CLEVERCLOUD_SECRET",
             r"clevercloud[_-]?(?:api[_-]?)?(?:secret|token)", "https://www.clever-cloud.com/developers/api/howto/"),
            ("coolify-api-token-v1", "Coolify API token", "coolify", "COOLIFY_TOKEN",
             r"coolify[_-]?(?:api[_-]?)?token", "https://coolify.io/docs/api-reference/authorization"),
            # payment / billing
            ("zuora-client-secret-v1", "Zuora client secret", "zuora", "ZUORA_SECRET",
             r"zuora[_-]?(?:client[_-]?)?secret", "https://www.zuora.com/developer/api-references/api/overview/"),
            ("sumup-client-secret-v1", "SumUp client secret", "sumup", "SUMUP_SECRET",
             r"sumup[_-]?(?:client[_-]?)?secret", "https://developer.sumup.com/api"),
            # scraping / browser infra
            ("scrapingant-api-key-v1", "ScrapingAnt API key", "scrapingant", "SCRAPINGANT_KEY",
             r"scrapingant[_-]?(?:api[_-]?)?key", "https://docs.scrapingant.com/"),
            ("browserbase-api-key-v1", "Browserbase API key", "browserbase", "BROWSERBASE_KEY",
             r"browserbase[_-]?(?:api[_-]?)?key", "https://docs.browserbase.com/"),
            ("hyperbrowser-api-key-v1", "Hyperbrowser API key", "hyperbrowser", "HYPERBROWSER_KEY",
             r"hyperbrowser[_-]?(?:api[_-]?)?key", "https://docs.hyperbrowser.ai/"),
            # CRM
            ("attio-api-key-v1", "Attio API key", "attio", "ATTIO_KEY",
             r"attio[_-]?(?:api[_-]?)?key", "https://developers.attio.com/reference/get_v2-objects"),
            # trading / exchanges
            ("alpaca-api-key-v1", "Alpaca API key", "alpaca", "ALPACA_KEY",
             r"alpaca[_-]?(?:api[_-]?)?(?:key|secret)", "https://docs.alpaca.markets/docs/authentication"),
            ("tradier-access-token-v1", "Tradier access token", "tradier", "TRADIER_TOKEN",
             r"tradier[_-]?(?:access[_-]?)?token", "https://documentation.tradier.com/brokerage-api/overview/endpoints"),
            ("binance-api-key-v1", "Binance API key", "binance", "BINANCE_KEY",
             r"binance[_-]?(?:api[_-]?)?(?:key|secret)", "https://developers.binance.com/docs/binance-spot-api-docs/rest-api"),
            ("kraken-api-key-v1", "Kraken API key", "kraken", "KRAKEN_KEY",
             r"kraken[_-]?(?:api[_-]?)?(?:key|secret)", "https://docs.kraken.com/rest/"),
            ("kucoin-api-secret-v1", "KuCoin API secret", "kucoin", "KUCOIN_SECRET",
             r"kucoin[_-]?(?:api[_-]?)?(?:secret|passphrase)", "https://www.kucoin.com/docs/basic-info/connection-method/authentication/creating-a-request"),
            ("bybit-api-key-v1", "Bybit API key", "bybit", "BYBIT_KEY",
             r"bybit[_-]?(?:api[_-]?)?(?:key|secret)", "https://bybit-exchange.github.io/docs/v5/intro"),
            ("okx-api-secret-v1", "OKX API secret", "okx", "OKX_SECRET",
             r"okx[_-]?(?:api[_-]?)?(?:secret|passphrase)", "https://www.okx.com/docs-v5/en/"),
        ]),

        # ---- thirty-fourth batch: dev / push / payments / maps / crypto-data ----
        *_labelled_batch([
            # dev platforms
            ("gitpod-token-v1", "Gitpod API token", "gitpod", "GITPOD_TOKEN",
             r"gitpod[_-]?(?:api[_-]?)?token", "https://www.gitpod.io/docs/references/gitpod-cli"),
            ("coder-session-token-v1", "Coder session token", "coder", "CODER_TOKEN",
             r"coder[_-]?(?:session[_-]?|api[_-]?)?token", "https://coder.com/docs/reference/api/authentication"),
            ("replit-token-v1", "Replit token", "replit", "REPLIT_TOKEN",
             r"replit[_-]?(?:db[_-]?|api[_-]?)?token", "https://docs.replit.com/"),
            ("codesandbox-token-v1", "CodeSandbox API token", "codesandbox", "CODESANDBOX_TOKEN",
             r"codesandbox[_-]?(?:api[_-]?)?token", "https://codesandbox.io/docs/sdk"),
            ("nhost-admin-secret-v1", "Nhost admin secret", "nhost", "NHOST_ADMIN_SECRET",
             r"nhost[_-]?(?:admin[_-]?)?secret", "https://docs.nhost.io/"),
            # push / engagement
            ("expo-access-token-v1", "Expo access token", "expo", "EXPO_TOKEN",
             r"expo[_-]?(?:access[_-]?)?token", "https://docs.expo.dev/accounts/programmatic-access/"),
            ("airship-app-secret-v1", "Airship app secret", "airship", "AIRSHIP_SECRET",
             r"airship[_-]?(?:app[_-]?)?(?:key|secret)", "https://docs.airship.com/api/ua/"),
            ("clevertap-passcode-v1", "CleverTap passcode", "clevertap", "CLEVERTAP_PASSCODE",
             r"clevertap[_-]?(?:account[_-]?)?passcode", "https://developer.clevertap.com/docs/api-overview"),
            ("moengage-app-key-v1", "MoEngage app key", "moengage", "MOENGAGE_KEY",
             r"moengage[_-]?(?:api[_-]?|app[_-]?)?key", "https://developers.moengage.com/hc/en-us"),
            ("smartlook-api-token-v1", "Smartlook API token", "smartlook", "SMARTLOOK_TOKEN",
             r"smartlook[_-]?(?:api[_-]?)?token", "https://developer.smartlook.com/reference/authentication"),
            # payments (global / India)
            ("fastspring-password-v1", "FastSpring API password", "fastspring", "FASTSPRING_PASSWORD",
             r"fastspring[_-]?(?:api[_-]?)?password", "https://developer.fastspring.com/docs/authentication"),
            ("paytm-merchant-key-v1", "Paytm merchant key", "paytm", "PAYTM_KEY",
             r"paytm[_-]?(?:merchant[_-]?)?key", "https://business.paytm.com/docs/"),
            ("cashfree-secret-key-v1", "Cashfree secret key", "cashfree", "CASHFREE_SECRET_KEY",
             r"cashfree[_-]?(?:secret[_-]?)?key", "https://docs.cashfree.com/reference/authentication"),
            ("phonepe-salt-key-v1", "PhonePe salt key", "phonepe", "PHONEPE_SALT_KEY",
             r"phonepe[_-]?(?:salt[_-]?)?key", "https://developer.phonepe.com/"),
            ("instamojo-auth-token-v1", "Instamojo auth token", "instamojo", "INSTAMOJO_TOKEN",
             r"instamojo[_-]?(?:api[_-]?|auth[_-]?)?token", "https://docs.instamojo.com/"),
            ("payu-merchant-salt-v1", "PayU merchant salt", "payu", "PAYU_SALT",
             r"payu[_-]?(?:merchant[_-]?)?(?:key|salt)", "https://docs.payu.in/"),
            # maps / location
            ("mapquest-api-key-v1", "MapQuest API key", "mapquest", "MAPQUEST_KEY",
             r"mapquest[_-]?(?:api[_-]?)?key", "https://developer.mapquest.com/documentation"),
            ("locationiq-api-key-v1", "LocationIQ API key", "locationiq", "LOCATIONIQ_KEY",
             r"locationiq[_-]?(?:api[_-]?)?key", "https://docs.locationiq.com/docs"),
            ("what3words-api-key-v1", "what3words API key", "what3words", "WHAT3WORDS_KEY",
             r"what3words[_-]?(?:api[_-]?)?key", "https://developer.what3words.com/public-api"),
            ("foursquare-api-key-v1", "Foursquare API key", "foursquare", "FOURSQUARE_KEY",
             r"foursquare[_-]?(?:api[_-]?)?key", "https://location.foursquare.com/developer/reference/places-api-overview"),
            # analytics
            ("countly-api-key-v1", "Countly API key", "countly", "COUNTLY_KEY",
             r"countly[_-]?(?:api[_-]?)?key", "https://api.count.ly/reference"),
            # NLP
            ("nlpcloud-api-token-v1", "NLP Cloud API token", "nlpcloud", "NLPCLOUD_TOKEN",
             r"nlpcloud[_-]?(?:api[_-]?)?token", "https://docs.nlpcloud.com/"),
            ("gooseai-api-key-v1", "GooseAI API key", "gooseai", "GOOSEAI_KEY",
             r"gooseai[_-]?(?:api[_-]?)?key", "https://goose.ai/docs"),
            ("sapling-api-key-v1", "Sapling API key", "sapling", "SAPLING_KEY",
             r"sapling[_-]?(?:api[_-]?)?key", "https://sapling.ai/docs/"),
            ("textrazor-api-key-v1", "TextRazor API key", "textrazor", "TEXTRAZOR_KEY",
             r"textrazor[_-]?(?:api[_-]?)?key", "https://www.textrazor.com/documentation"),
            # crypto / blockchain data
            ("coinapi-api-key-v1", "CoinAPI key", "coinapi", "COINAPI_KEY",
             r"coinapi[_-]?(?:api[_-]?)?key", "https://docs.coinapi.io/"),
            ("cryptocompare-api-key-v1", "CryptoCompare API key", "cryptocompare", "CRYPTOCOMPARE_KEY",
             r"cryptocompare[_-]?(?:api[_-]?)?key", "https://developers.cryptocompare.com/"),
            ("messari-api-key-v1", "Messari API key", "messari", "MESSARI_KEY",
             r"messari[_-]?(?:api[_-]?)?key", "https://messari.io/api/docs"),
            ("covalent-api-key-v1", "Covalent API key", "covalent", "COVALENT_KEY",
             r"covalent[_-]?(?:api[_-]?)?key", "https://www.covalenthq.com/docs/api/"),
            ("blockcypher-token-v1", "BlockCypher token", "blockcypher", "BLOCKCYPHER_TOKEN",
             r"blockcypher[_-]?(?:api[_-]?)?token", "https://www.blockcypher.com/dev/bitcoin/"),
            ("ankr-api-key-v1", "Ankr API key", "ankr", "ANKR_KEY",
             r"ankr[_-]?(?:api[_-]?)?key", "https://www.ankr.com/docs/"),
            ("chainstack-api-key-v1", "Chainstack API key", "chainstack", "CHAINSTACK_KEY",
             r"chainstack[_-]?(?:api[_-]?)?key", "https://docs.chainstack.com/reference/platform-api-getting-started"),
            ("helius-api-key-v1", "Helius API key", "helius", "HELIUS_KEY",
             r"helius[_-]?(?:api[_-]?)?key", "https://docs.helius.dev/"),
        ]),

        # ---- thirty-fifth batch: security / monitoring / regional payments / SMS ----
        *_labelled_batch([
            # email deliverability
            ("ortto-api-key-v1", "Ortto API key", "ortto", "ORTTO_KEY",
             r"ortto[_-]?(?:api[_-]?)?key", "https://help.ortto.com/developer/latest/api-reference/"),
            ("bouncer-api-key-v1", "Bouncer API key", "bouncer", "BOUNCER_KEY",
             r"bouncer[_-]?(?:api[_-]?)?key", "https://docs.usebouncer.com/"),
            ("debounce-api-key-v1", "DeBounce API key", "debounce", "DEBOUNCE_KEY",
             r"debounce[_-]?(?:api[_-]?)?key", "https://debounce.io/resources/docs/"),
            # security / appsec
            ("checkmarx-client-secret-v1", "Checkmarx client secret", "checkmarx", "CHECKMARX_SECRET",
             r"checkmarx[_-]?(?:client[_-]?)?secret", "https://docs.checkmarx.com/"),
            ("fossa-api-key-v1", "FOSSA API key", "fossa", "FOSSA_KEY",
             r"fossa[_-]?(?:api[_-]?)?(?:key|token)", "https://docs.fossa.com/docs/api-reference"),
            ("mend-api-key-v1", "Mend (WhiteSource) API key", "mend", "MEND_KEY",
             r"mend[_-]?(?:api[_-]?)?key", "https://docs.mend.io/"),
            ("socketdev-api-token-v1", "Socket.dev API token", "socketdev", "SOCKETDEV_TOKEN",
             r"socketdev[_-]?(?:api[_-]?)?token", "https://docs.socket.dev/reference/introduction-to-socket-api"),
            ("aikido-api-key-v1", "Aikido Security API key", "aikido", "AIKIDO_KEY",
             r"aikido[_-]?(?:api[_-]?)?(?:key|token)", "https://apidocs.aikido.dev/"),
            ("orca-security-token-v1", "Orca Security API token", "orca", "ORCA_TOKEN",
             r"orca[_-]?(?:security[_-]?)?(?:api[_-]?)?token", "https://docs.orcasecurity.io/"),
            ("sysdig-secure-token-v1", "Sysdig Secure API token", "sysdig", "SYSDIG_TOKEN",
             r"sysdig[_-]?(?:api[_-]?|secure[_-]?)?token", "https://docs.sysdig.com/en/docs/developer-tools/sysdig-python-client/"),
            ("prismacloud-access-key-v1", "Prisma Cloud access key", "prismacloud", "PRISMACLOUD_KEY",
             r"prismacloud[_-]?(?:access[_-]?)?key", "https://pan.dev/prisma-cloud/api/cspm/"),
            # monitoring
            ("netdata-cloud-token-v1", "Netdata Cloud token", "netdata", "NETDATA_TOKEN",
             r"netdata[_-]?(?:cloud[_-]?)?(?:api[_-]?)?token", "https://learn.netdata.cloud/docs/netdata-cloud/api-tokens"),
            ("uptrace-dsn-v1", "Uptrace DSN", "uptrace", "UPTRACE_DSN",
             r"uptrace[_-]?(?:dsn|token)", "https://uptrace.dev/get/get-started.html"),
            ("middleware-api-key-v1", "Middleware.io API key", "middleware", "MIDDLEWARE_KEY",
             r"middleware[_-]?(?:api[_-]?)?key", "https://docs.middleware.io/"),
            # cloud / bare metal
            ("latitude-api-token-v1", "Latitude.sh API token", "latitude", "LATITUDE_TOKEN",
             r"latitude[_-]?(?:sh[_-]?)?(?:api[_-]?)?token", "https://docs.latitude.sh/reference/getting-started-with-the-api"),
            ("cherryservers-api-key-v1", "Cherry Servers API key", "cherryservers", "CHERRYSERVERS_KEY",
             r"cherryservers[_-]?(?:api[_-]?)?(?:key|token)", "https://api.cherryservers.com/doc/"),
            ("stackpath-client-secret-v1", "StackPath client secret", "stackpath", "STACKPATH_SECRET",
             r"stackpath[_-]?(?:client[_-]?)?secret", "https://stackpath.dev/docs/getting-started/"),
            # regional payments
            ("midtrans-server-key-v1", "Midtrans server key", "midtrans", "MIDTRANS_SERVER_KEY",
             r"midtrans[_-]?(?:server[_-]?)?key", "https://docs.midtrans.com/docs/technical-reference-introduction"),
            ("xendit-secret-key-v1", "Xendit secret key", "xendit", "XENDIT_SECRET_KEY",
             r"xendit[_-]?(?:secret[_-]?)?key", "https://developers.xendit.co/api-reference/"),
            ("paymongo-secret-key-v1", "PayMongo secret key", "paymongo", "PAYMONGO_SECRET_KEY",
             r"paymongo[_-]?(?:secret[_-]?)?key", "https://developers.paymongo.com/docs/authentication"),
            ("iyzico-secret-key-v1", "iyzico secret key", "iyzico", "IYZICO_SECRET_KEY",
             r"iyzico[_-]?(?:secret[_-]?)?key", "https://docs.iyzico.com/en"),
            ("mpesa-consumer-secret-v1", "M-Pesa consumer secret", "mpesa", "MPESA_SECRET",
             r"mpesa[_-]?(?:consumer[_-]?)?secret", "https://developer.safaricom.co.ke/"),
            ("conekta-api-key-v1", "Conekta API key", "conekta", "CONEKTA_KEY",
             r"conekta[_-]?(?:api[_-]?|private[_-]?)?key", "https://developers.conekta.com/"),
            ("mercadopago-access-token-v1", "Mercado Pago access token", "mercadopago", "MERCADOPAGO_TOKEN",
             r"mercadopago[_-]?(?:access[_-]?)?token", "https://www.mercadopago.com/developers/en/docs"),
            ("pagarme-api-key-v1", "Pagar.me API key", "pagarme", "PAGARME_KEY",
             r"pagarme[_-]?(?:api[_-]?|secret[_-]?)?key", "https://docs.pagar.me/"),
            ("openpay-private-key-v1", "Openpay private key", "openpay", "OPENPAY_PRIVATE_KEY",
             r"openpay[_-]?(?:api[_-]?|private[_-]?)?key", "https://www.openpay.mx/en/docs/"),
            # regional SMS
            ("msg91-auth-key-v1", "MSG91 auth key", "msg91", "MSG91_KEY",
             r"msg91[_-]?(?:auth[_-]?)?key", "https://docs.msg91.com/"),
            ("gupshup-api-key-v1", "Gupshup API key", "gupshup", "GUPSHUP_KEY",
             r"gupshup[_-]?(?:api[_-]?)?key", "https://docs.gupshup.io/"),
            ("textlocal-api-key-v1", "Textlocal API key", "textlocal", "TEXTLOCAL_KEY",
             r"textlocal[_-]?(?:api[_-]?)?key", "https://api.textlocal.in/docs/"),
            ("fast2sms-api-key-v1", "Fast2SMS API key", "fast2sms", "FAST2SMS_KEY",
             r"fast2sms[_-]?(?:api[_-]?)?key", "https://docs.fast2sms.com/"),
            # feature flags / marketing / video
            ("growthbook-api-key-v1", "GrowthBook API key", "growthbook", "GROWTHBOOK_KEY",
             r"growthbook[_-]?(?:api[_-]?)?(?:key|secret)", "https://docs.growthbook.io/api"),
            ("eppo-api-key-v1", "Eppo API key", "eppo", "EPPO_KEY",
             r"eppo[_-]?(?:api[_-]?)?key", "https://docs.geteppo.com/"),
            ("falai-api-key-v1", "fal.ai API key", "falai", "FALAI_KEY",
             r"falai[_-]?(?:api[_-]?)?key", "https://docs.fal.ai/authentication/key-based"),
            ("marketo-client-secret-v1", "Marketo client secret", "marketo", "MARKETO_SECRET",
             r"marketo[_-]?(?:client[_-]?)?secret", "https://developers.marketo.com/rest-api/authentication/"),
            ("bitmovin-api-key-v1", "Bitmovin API key", "bitmovin", "BITMOVIN_KEY",
             r"bitmovin[_-]?(?:api[_-]?)?key", "https://bitmovin.com/docs/encoding/api-reference"),
        ]),

        # ---- thirty-sixth batch: APIs / SEO / commerce / shipping / AI / DB / support ----
        *_labelled_batch([
            # gaming
            ("photon-app-secret-v1", "Photon app secret", "photon", "PHOTON_SECRET",
             r"photon[_-]?(?:app[_-]?)?(?:id|secret)", "https://doc.photonengine.com/realtime/current/reference/webhooks"),
            ("itchio-api-key-v1", "itch.io API key", "itchio", "ITCHIO_KEY",
             r"itchio[_-]?(?:api[_-]?)?key", "https://itch.io/docs/api/overview"),
            # generic API aggregators / data APIs
            ("rapidapi-key-v1", "RapidAPI key", "rapidapi", "RAPIDAPI_KEY",
             r"rapidapi[_-]?key", "https://docs.rapidapi.com/docs/keys-and-key-rotation"),
            ("apilayer-api-key-v1", "APILayer API key", "apilayer", "APILAYER_KEY",
             r"apilayer[_-]?(?:api[_-]?)?key", "https://apilayer.com/docs"),
            ("currencylayer-api-key-v1", "Currencylayer API key", "currencylayer", "CURRENCYLAYER_KEY",
             r"currencylayer[_-]?(?:api[_-]?)?key", "https://currencylayer.com/documentation"),
            ("fixer-api-key-v1", "Fixer API key", "fixer", "FIXER_KEY",
             r"fixer[_-]?(?:api[_-]?)?key", "https://fixer.io/documentation"),
            ("exchangerate-api-key-v1", "ExchangeRate-API key", "exchangerate", "EXCHANGERATE_KEY",
             r"exchangerate[_-]?(?:api[_-]?)?key", "https://www.exchangerate-api.com/docs/overview"),
            ("openexchangerates-app-id-v1", "Open Exchange Rates app id", "openexchangerates", "OPENEXCHANGERATES_ID",
             r"openexchangerates[_-]?(?:app[_-]?)?(?:id|key)", "https://docs.openexchangerates.org/reference/authentication"),
            ("ipstack-access-key-v1", "ipstack access key", "ipstack", "IPSTACK_KEY",
             r"ipstack[_-]?(?:api[_-]?|access[_-]?)?key", "https://ipstack.com/documentation"),
            ("ip2location-api-key-v1", "IP2Location API key", "ip2location", "IP2LOCATION_KEY",
             r"ip2location[_-]?(?:api[_-]?)?key", "https://www.ip2location.io/ip2location-documentation"),
            ("ipapi-api-key-v1", "ipapi API key", "ipapi", "IPAPI_KEY",
             r"ipapi[_-]?(?:api[_-]?|access[_-]?)?key", "https://ipapi.com/documentation"),
            ("ipgeolocation-api-key-v1", "IPGeolocation API key", "ipgeolocation", "IPGEOLOCATION_KEY",
             r"ipgeolocation[_-]?(?:api[_-]?)?key", "https://ipgeolocation.io/documentation.html"),
            ("scrapingdog-api-key-v1", "Scrapingdog API key", "scrapingdog", "SCRAPINGDOG_KEY",
             r"scrapingdog[_-]?(?:api[_-]?)?key", "https://www.scrapingdog.com/documentation"),
            # search / SEO
            ("kagi-api-token-v1", "Kagi API token", "kagi", "KAGI_TOKEN",
             r"kagi[_-]?(?:api[_-]?)?(?:key|token)", "https://help.kagi.com/kagi/api/search.html"),
            ("brave-search-key-v1", "Brave Search API key", "brave", "BRAVE_SEARCH_KEY",
             r"brave[_-]?(?:search[_-]?)?(?:api[_-]?)?key", "https://brave.com/search/api/"),
            ("bing-search-key-v1", "Bing Search API key", "bing", "BING_SEARCH_KEY",
             r"bing[_-]?(?:search[_-]?)?(?:api[_-]?)?key", "https://www.microsoft.com/en-us/bing/apis/bing-web-search-api"),
            ("serpstack-access-key-v1", "Serpstack access key", "serpstack", "SERPSTACK_KEY",
             r"serpstack[_-]?(?:api[_-]?|access[_-]?)?key", "https://serpstack.com/documentation"),
            ("valueserp-api-key-v1", "ValueSERP API key", "valueserp", "VALUESERP_KEY",
             r"valueserp[_-]?(?:api[_-]?)?key", "https://docs.valueserp.com/"),
            ("dataforseo-password-v1", "DataForSEO password", "dataforseo", "DATAFORSEO_PASSWORD",
             r"dataforseo[_-]?(?:api[_-]?|login[_-]?)?(?:key|password)", "https://docs.dataforseo.com/v3/auth/"),
            ("semrush-api-key-v1", "Semrush API key", "semrush", "SEMRUSH_KEY",
             r"semrush[_-]?(?:api[_-]?)?key", "https://developer.semrush.com/api/"),
            ("ahrefs-api-token-v1", "Ahrefs API token", "ahrefs", "AHREFS_TOKEN",
             r"ahrefs[_-]?(?:api[_-]?)?(?:key|token)", "https://docs.ahrefs.com/docs/api/reference/authentication"),
            ("moz-api-token-v1", "Moz API token", "moz", "MOZ_TOKEN",
             r"moz[_-]?(?:api[_-]?|access[_-]?)?(?:id|token)", "https://moz.com/help/links-api/making-calls/authentication"),
            # commerce / marketplace
            ("ebay-client-secret-v1", "eBay client secret", "ebay", "EBAY_SECRET",
             r"ebay[_-]?(?:client[_-]?)?secret", "https://developer.ebay.com/api-docs/static/oauth-tokens.html"),
            ("etsy-keystring-v1", "Etsy keystring", "etsy", "ETSY_KEYSTRING",
             r"etsy[_-]?(?:api[_-]?)?(?:keystring|key)", "https://developers.etsy.com/documentation/essentials/authentication"),
            ("walmart-client-secret-v1", "Walmart client secret", "walmart", "WALMART_SECRET",
             r"walmart[_-]?(?:client[_-]?)?secret", "https://developer.walmart.com/doc/us/us-mp/us-mp-auth/"),
            ("faire-api-token-v1", "Faire API token", "faire", "FAIRE_TOKEN",
             r"faire[_-]?(?:api[_-]?)?(?:key|token)", "https://faire.github.io/external-api-v2-docs/"),
            ("printful-api-key-v1", "Printful API key", "printful", "PRINTFUL_KEY",
             r"printful[_-]?(?:api[_-]?)?key", "https://developers.printful.com/docs/"),
            ("printify-api-token-v1", "Printify API token", "printify", "PRINTIFY_TOKEN",
             r"printify[_-]?(?:api[_-]?)?token", "https://developers.printify.com/"),
            ("gelato-api-key-v1", "Gelato API key", "gelato", "GELATO_KEY",
             r"gelato[_-]?(?:api[_-]?)?key", "https://dashboard.gelato.com/docs/"),
            # shipping
            ("shiprocket-token-v1", "Shiprocket API token", "shiprocket", "SHIPROCKET_TOKEN",
             r"shiprocket[_-]?(?:api[_-]?)?token", "https://apidocs.shiprocket.in/"),
            ("easyship-token-v1", "Easyship API token", "easyship", "EASYSHIP_TOKEN",
             r"easyship[_-]?(?:api[_-]?)?token", "https://developers.easyship.com/reference/authentication"),
            ("shipbob-token-v1", "ShipBob access token", "shipbob", "SHIPBOB_TOKEN",
             r"shipbob[_-]?(?:api[_-]?|access[_-]?)?token", "https://developer.shipbob.com/auth"),
            # tunneling / networking
            ("ngrok-authtoken-v1", "ngrok authtoken", "ngrok", "NGROK_TOKEN",
             r"ngrok[_-]?(?:api[_-]?|auth[_-]?)?token", "https://ngrok.com/docs/agent/#authtokens"),
            ("zerotier-api-token-v1", "ZeroTier API token", "zerotier", "ZEROTIER_TOKEN",
             r"zerotier[_-]?(?:api[_-]?)?token", "https://docs.zerotier.com/central/v1"),
            # more AI
            ("sarvam-api-key-v1", "Sarvam AI API key", "sarvam", "SARVAM_KEY",
             r"sarvam[_-]?(?:api[_-]?)?key", "https://docs.sarvam.ai/"),
            ("venice-api-key-v1", "Venice AI API key", "venice", "VENICE_KEY",
             r"venice[_-]?(?:ai[_-]?)?(?:api[_-]?)?key", "https://docs.venice.ai/"),
            ("featherless-api-key-v1", "Featherless API key", "featherless", "FEATHERLESS_KEY",
             r"featherless[_-]?(?:api[_-]?)?key", "https://featherless.ai/docs"),
            # databases
            ("dgraph-api-key-v1", "Dgraph Cloud API key", "dgraph", "DGRAPH_KEY",
             r"dgraph[_-]?(?:cloud[_-]?)?(?:api[_-]?)?(?:key|token)", "https://dgraph.io/docs/cloud/"),
            ("rockset-api-key-v1", "Rockset API key", "rockset", "ROCKSET_KEY",
             r"rockset[_-]?(?:api[_-]?)?key", "https://docs.rockset.com/documentation/reference/rest-api"),
            ("materialize-password-v1", "Materialize app password", "materialize", "MATERIALIZE_PASSWORD",
             r"materialize[_-]?(?:app[_-]?)?password", "https://materialize.com/docs/manage/access-control/"),
            # more monitoring
            ("signoz-ingestion-key-v1", "SigNoz ingestion key", "signoz", "SIGNOZ_KEY",
             r"signoz[_-]?(?:ingestion[_-]?|api[_-]?)?key", "https://signoz.io/docs/ingestion/signoz-cloud/keys/"),
            ("hyperdx-api-key-v1", "HyperDX API key", "hyperdx", "HYPERDX_KEY",
             r"hyperdx[_-]?(?:api[_-]?)?key", "https://www.hyperdx.io/docs"),
            ("openobserve-token-v1", "OpenObserve token", "openobserve", "OPENOBSERVE_TOKEN",
             r"openobserve[_-]?(?:api[_-]?)?(?:key|token)", "https://openobserve.ai/docs/"),
            # support / chat / marketing
            ("gohighlevel-api-key-v1", "GoHighLevel API key", "gohighlevel", "GOHIGHLEVEL_KEY",
             r"gohighlevel[_-]?(?:api[_-]?)?key", "https://highlevel.stoplight.io/docs/integrations/"),
            ("chatwoot-access-token-v1", "Chatwoot access token", "chatwoot", "CHATWOOT_TOKEN",
             r"chatwoot[_-]?(?:api[_-]?|access[_-]?)?token", "https://www.chatwoot.com/developers/api/"),
            ("tawk-api-key-v1", "Tawk.to API key", "tawk", "TAWK_KEY",
             r"tawk[_-]?(?:to[_-]?)?(?:api[_-]?)?key", "https://developer.tawk.to/rest-api/"),
            ("livechat-client-secret-v1", "LiveChat client secret", "livechat", "LIVECHAT_SECRET",
             r"livechat[_-]?(?:client[_-]?)?secret", "https://developers.livechat.com/docs/authorization"),
            ("abtasty-api-key-v1", "AB Tasty API key", "abtasty", "ABTASTY_KEY",
             r"abtasty[_-]?(?:api[_-]?)?key", "https://developers.abtasty.com/"),
            ("unbounce-token-v1", "Unbounce API token", "unbounce", "UNBOUNCE_TOKEN",
             r"unbounce[_-]?(?:api[_-]?)?(?:key|token)", "https://developer.unbounce.com/api_reference/"),
            ("paperform-api-key-v1", "Paperform API key", "paperform", "PAPERFORM_KEY",
             r"paperform[_-]?(?:api[_-]?)?key", "https://paperform.co/support/articles/api/"),
            ("fillout-api-key-v1", "Fillout API key", "fillout", "FILLOUT_KEY",
             r"fillout[_-]?(?:api[_-]?)?key", "https://www.fillout.com/help/fillout-rest-api"),
        ]),
    ]
    return d
