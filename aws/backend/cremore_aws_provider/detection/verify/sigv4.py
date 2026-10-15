"""AWS Signature Version 4 signing (from the AWS public specification).

Implemented from the documented SigV4 algorithm:
https://docs.aws.amazon.com/IAM/latest/UserGuide/create-signed-request.html

Only what a GetCallerIdentity probe needs is implemented: a signed POST with a
form body and the standard host / x-amz-date / content-type headers.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import hmac
from dataclasses import dataclass

_ALGORITHM = "AWS4-HMAC-SHA256"


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hmac(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def _signing_key(secret: str, datestamp: str, region: str, service: str) -> bytes:
    k_date = _hmac(("AWS4" + secret).encode("utf-8"), datestamp)
    k_region = _hmac(k_date, region)
    k_service = _hmac(k_region, service)
    return _hmac(k_service, "aws4_request")


@dataclass(frozen=True)
class SignedRequest:
    url: str
    headers: dict[str, str]
    body: bytes


def sign(
    *,
    access_key_id: str,
    secret_access_key: str,
    region: str,
    service: str,
    host: str,
    body: bytes,
    content_type: str = "application/x-www-form-urlencoded; charset=utf-8",
    session_token: str = "",
    now: _dt.datetime | None = None,
) -> SignedRequest:
    """Return the signed URL, headers and body for a POST to ``/`` on ``host``."""

    moment = (now or _dt.datetime.now(_dt.UTC)).astimezone(_dt.UTC)
    amz_date = moment.strftime("%Y%m%dT%H%M%SZ")
    datestamp = moment.strftime("%Y%m%d")

    canonical_uri = "/"
    canonical_querystring = ""
    payload_hash = _sha256_hex(body)

    # Signed headers, in the lowercase-sorted order the spec requires.
    headers_to_sign: dict[str, str] = {
        "content-type": content_type,
        "host": host,
        "x-amz-date": amz_date,
    }
    if session_token:
        headers_to_sign["x-amz-security-token"] = session_token

    signed_headers = ";".join(sorted(headers_to_sign))
    canonical_headers = "".join(
        f"{name}:{headers_to_sign[name].strip()}\n" for name in sorted(headers_to_sign)
    )

    canonical_request = "\n".join(  # noqa: FLY002 -- Keep AWS canonical-request field ordering explicit for signature review.
        [
            "POST",
            canonical_uri,
            canonical_querystring,
            canonical_headers,
            signed_headers,
            payload_hash,
        ]
    )

    scope = f"{datestamp}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join(
        [_ALGORITHM, amz_date, scope, _sha256_hex(canonical_request.encode("utf-8"))]
    )

    signature = hmac.new(
        _signing_key(secret_access_key, datestamp, region, service),
        string_to_sign.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    authorization = (
        f"{_ALGORITHM} Credential={access_key_id}/{scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )

    out_headers = {
        "Content-Type": content_type,
        "X-Amz-Date": amz_date,
        "Authorization": authorization,
    }
    if session_token:
        out_headers["X-Amz-Security-Token"] = session_token

    return SignedRequest(url=f"https://{host}/", headers=out_headers, body=body)
