"""AWS access-key verifier.

Signs a real ``sts:GetCallerIdentity`` request with the discovered key using
SigV4 and reads the provider's answer. GetCallerIdentity is the safe probe: it
takes no parameters, changes nothing, and requires no permissions beyond a valid
identity, so a working key returns its own ARN and an invalid key is rejected.

A long-lived ``AKIA`` pair is probed with its id and secret. A temporary
``ASIA`` credential authenticates only as a bound triple, so it is probed only
when the detection boundary supplies its session token (``aws_session_token`` in
the verify context) as the signed ``x-amz-security-token`` header; the id and
secret alone stay ``unsupported``. Success proves the session authenticates at
this moment, never what it is permitted to do (GetCallerIdentity needs no
permission, and an explicit deny of it still returns the identity).

Docs: https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html
"""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET

from cremore.detection.verify import (
    VerificationResult,
    VerificationState,
    VerifierConfig,
    register,
)
from cremore.http_client import bounded_request
from cremore_aws_provider.detection.verify.sigv4 import sign

_STS_HOST = "sts.amazonaws.com"
_STS_REGION = "us-east-1"
_STS_BODY = b"Action=GetCallerIdentity&Version=2011-06-15"

# Access-key ids are documented as (AKIA|ASIA) + 16 base32 chars; a secret access
# key is 40 base64 chars. We only probe when both halves are present.
_AKID = re.compile(r"^(?:AKIA|ASIA)[A-Z0-9]{16}$")
_SECRET = re.compile(r"^[A-Za-z0-9/+=]{40}$")
# A bound STS session token is opaque base64-ish material, length-capped in the
# detection boundary. Re-validate here because it becomes a signed request
# header: it must carry no control characters or header separators.
_SESSION_TOKEN = re.compile(r"^[A-Za-z0-9/+=]{16,8192}$")

# STS error codes that mean "this credential is not valid" (a definite rejection)
# versus transient/ambiguous conditions that must not be read as revocation.
# Expired session tokens are a definite "does not authenticate now" for ASIA.
_REJECTION_CODES = {"InvalidClientTokenId", "AuthFailure", "ExpiredToken", "ExpiredTokenException"}


def _session_token(context: dict | None) -> str:
    """The validated bound session token from the verify context, or ``""``."""
    token = (context or {}).get("aws_session_token", "")
    if isinstance(token, bytes):
        token = token.decode("ascii", "ignore")
    if isinstance(token, str) and "\\" in token:
        # The binding span preserves JSON escapes for redaction; signing needs the decoded value.
        try:
            token = json.loads('"' + token + '"')
        except ValueError:
            return ""
    return token if isinstance(token, str) and _SESSION_TOKEN.fullmatch(token) else ""


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


class AWSAccessKeyVerifier:
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
        if not (_AKID.fullmatch(identifier) and _SECRET.fullmatch(secret)):
            return VerificationResult(
                VerificationState.UNSUPPORTED, error_code="AWS_KEY_PAIR_INCOMPLETE"
            )
        session_token = ""
        if identifier.startswith("ASIA"):
            # A temporary credential authenticates only as a bound triple. Without
            # the session token, id and secret alone cannot establish validity, so
            # stay silent rather than send an unverifiable request.
            session_token = _session_token(context)
            if not session_token:
                return VerificationResult(
                    VerificationState.UNSUPPORTED, error_code="AWS_STS_SESSION_TOKEN_NOT_BOUND"
                )
        return self._probe(identifier, secret, session_token, config, client)

    def _probe(
        self, identifier: str, secret: str, session_token: str, config: VerifierConfig, client: object | None
    ) -> VerificationResult:
        """Sign and send the GetCallerIdentity probe, then read the answer."""

        signed = sign(
            access_key_id=identifier,
            secret_access_key=secret,
            region=_STS_REGION,
            service="sts",
            host=_STS_HOST,
            body=_STS_BODY,
            session_token=session_token,
        )

        owns_client = client is None
        if client is None:
            import httpx

            client = httpx.Client(timeout=config.timeout)
        try:
            resp = bounded_request(
                client, "POST", signed.url, headers=signed.headers, content=signed.body
            )
        except Exception:  # noqa: BLE001 -- Transport failures cannot prove credential invalidity; do not expose request secrets.
            return VerificationResult(
                VerificationState.INDETERMINATE, error_code="AWS_STS_UNREACHABLE"
            )
        finally:
            if owns_client:
                try:
                    client.close()
                except Exception:  # noqa: BLE001, S110 -- Best-effort close must not replace the result or log credential-bearing errors.
                    pass

        return self._interpret(resp.status_code, resp.text)

    @staticmethod
    def _interpret(status: int, text: str) -> VerificationResult:
        try:
            root = ET.fromstring(text)
        except ET.ParseError:
            return VerificationResult(
                VerificationState.INDETERMINATE, error_code="AWS_STS_UNPARSEABLE"
            )
        tags = {_local(el.tag): (el.text or "").strip() for el in root.iter()}
        if status == 200 and "Arn" in tags:
            return VerificationResult(
                VerificationState.VERIFIED,
                facts={
                    name: value for name, tag in (("arn", "Arn"), ("account", "Account"), ("user_id", "UserId"))
                    if (value := tags.get(tag, "")) and len(value) <= 256 and value.isprintable()
                },
            )
        code = tags.get("Code", "")
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,79}", code):
            code = ""
        if code in _REJECTION_CODES:
            return VerificationResult(VerificationState.REJECTED, error_code=code)
        return VerificationResult(
            VerificationState.INDETERMINATE, error_code=code or f"HTTP_{status}"
        )


def register_all() -> None:
    register("aws-access-key-pair-v1", AWSAccessKeyVerifier())
