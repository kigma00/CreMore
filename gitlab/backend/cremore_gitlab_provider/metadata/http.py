"""HTTPS 읽기 전용 전송: 요청 제한, 제한된 재시도, 페이지 경계 검증."""

import json
import logging
import math
import random
import re
import ssl
import time
from dataclasses import dataclass
from email.utils import parsedate_to_datetime
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request, build_opener

from . import __version__
from .config import Config
from .handlers import RATE_CLASSES
from .model import secret_field

LOG = logging.getLogger(__name__)


class CollectionError(Exception):
    """응답 본문·인증값을 포함하지 않는 구조화된 수집 오류."""

    def __init__(
        self, code: str, message: str, status: int | None = None, details: dict | None = None
    ):
        """오류 코드, 안전한 설명, HTTP 상태만 보관한다."""
        super().__init__(message)
        self.code, self.status = code, status
        self.details = details or {}


@dataclass
class Response:
    """요청 결과. 이 객체의 body를 저장하기 전에 항상 sanitize한다."""

    body: object
    headers: dict[str, str]


class NoRedirect(HTTPRedirectHandler):
    """인증 헤더가 다른 주소로 전달되지 않도록 자동 redirect를 거부한다."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        """3xx는 상위 요청 계층에서 명시적 오류로 처리한다."""
        return


class TokenBucket:
    """Credential과 무관한 요청 허용량 버킷. 단일 작업자에서 속도를 제어한다."""

    def __init__(self, rate: float, capacity: int, clock=time.monotonic, sleep=time.sleep):
        """테스트에서 실제 대기 없이 검증할 수 있도록 시계·대기를 주입한다."""
        self.rate, self.capacity = rate, capacity
        self.clock, self.sleep = clock, sleep
        self.balance, self.updated = float(capacity), clock()

    def delay(self) -> float:
        """충전만 반영해 다음 허가까지의 초를 알려준다. 기다리거나 허가를 차감하지 않는다."""
        current = self.clock()
        self.balance = min(self.capacity, self.balance + (current - self.updated) * self.rate)
        self.updated = current
        return max(0.0, (1 - self.balance) / self.rate)

    def acquire(self, *additional):
        """같은 시계를 쓰는 모든 버킷이 허용할 때만 동시에 차감한다. 단일 작업자 전용이다."""
        buckets = (self, *additional)
        while True:
            current = self.clock()
            for bucket in buckets:
                bucket.balance = min(bucket.capacity, bucket.balance + (current - bucket.updated) * bucket.rate)
                bucket.updated = current
            wait = max(max(0.0, (1 - bucket.balance) / bucket.rate) for bucket in buckets)
            if wait <= 0:
                # 따로 acquire하면 첫 버킷의 허가가 다른 대기 중 오래되어 짧은 간격의 전송이 가능하다.
                # 최종 전송 시점에 전역·사용자 제한을 함께 확인해 그 틈을 없앤다.
                for bucket in buckets:
                    bucket.balance -= 1
                return
            # 부동소수점 끝자리 차이 때문에 주입한 가상 시계가 전진하지 않는 반복도 방지한다.
            self.sleep(max(wait, 0.000001))


def retry_after(value: str | None, wall_time=time.time) -> float:
    """Retry-After의 초·HTTP-date 형식을 모두 읽는다."""
    if not value:
        return 0.0
    try:
        seconds = float(value)
        return max(0.0, seconds) if math.isfinite(seconds) else 0.0
    except ValueError:
        try:
            return max(0.0, parsedate_to_datetime(value).timestamp() - wall_time())
        except (ValueError, TypeError, OverflowError):
            return 0.0


def rate_limit_reset(value: str | None, wall_time=time.time) -> float:
    """GitLab RateLimit-Reset의 UNIX 시각을 대기 초로 바꾼다. 잘못된 값은 채택하지 않는다."""
    try:
        reset = float(value)
        return max(0.0, reset - wall_time()) if math.isfinite(reset) else 0.0
    except (ValueError, TypeError):
        return 0.0


class Client:
    """REST GET과 고정 GraphQL query만 전송한다. 변경 API는 구현하지 않는다."""

    def __init__(self, config: Config, token: str, opener=None, sleep=time.sleep, check=None, clock=time.monotonic):
        """TLS 기본 검증을 사용하며 환경 프록시의 암묵적 사용을 피한다."""
        # Reject non-header characters before urllib can leak a codec error to the UI.
        if not isinstance(token, str) or not token or any(ord(c) < 33 or ord(c) > 126 for c in token):
            raise CollectionError("INVALID_AUTH_TOKEN_FORMAT", "PAT 형식이 올바르지 않습니다.")
        self.config, self.token, self.sleep = config, token, sleep
        self.check = check or (lambda: None)
        self.origin = config.base_url.rstrip("/")
        self.bucket = TokenBucket(config.requests_per_second, config.burst, clock=clock, sleep=sleep)
        self.user_details_bucket = TokenBucket(config.user_details_requests_per_second, 1, clock=clock, sleep=sleep)
        self.opener = opener or build_opener(
            ProxyHandler({}), NoRedirect(), HTTPSHandler(context=ssl.create_default_context())
        )
        self.requests = 0
        self.retries = 0
        self.consecutive_rate_limits = 0

    def rate_class_delay(self, rate_class: str) -> float:
        """작업 선택에는 전용 버킷만 사용한다. 전역 제한은 실제 request에서 계속 적용한다."""
        if rate_class == "user_details":
            return self.user_details_bucket.delay()
        if rate_class == "default":
            return 0.0
        raise ValueError("지원하지 않는 속도 제한 분류입니다.")

    def deferred_rate_classes(self) -> frozenset[str]:
        """현재 전용 허가가 없는 분류를 반환한다. 재시도 대기를 우회하는 기능은 아니다."""
        return frozenset(name for name in RATE_CLASSES if name != "default" and self.rate_class_delay(name) > 0)

    def checked_url(self, url: str, graphql: bool = False) -> str:
        """동일 origin·API 경로만 허용하여 페이지 링크의 범위 이탈을 막는다."""
        absolute = urljoin(self.origin + "/", url)
        target, expected = urlsplit(absolute), urlsplit(self.origin)
        if (
            (target.scheme, target.netloc) != (expected.scheme, expected.netloc)
            or target.username
            or target.password
            or target.fragment
        ):
            raise CollectionError(
                "UNSAFE_URL", "페이지 링크가 설정한 GitLab origin을 벗어났습니다."
            )
        if not (target.path == "/api/graphql" if graphql else target.path.startswith("/api/v4/")):
            raise CollectionError("UNSAFE_URL", "지원하지 않는 API 경로입니다.")
        if any(
            secret_field(key, value)
            for key, value in parse_qsl(target.query, keep_blank_values=True)
        ):
            raise CollectionError("UNSAFE_URL", "페이지 링크의 인증 query는 허용하지 않습니다.")
        return absolute

    def rest_url(self, path: str, params: dict | None = None) -> str:
        """상대 REST 경로와 구조화된 query 인수를 URL로 만든다."""
        return self.checked_url("/api/v4" + path + ("?" + urlencode(params) if params else ""))

    def request(
        self, url: str, query: str | None = None, variables: dict | None = None
    ) -> Response:
        """일시적 실패만 재시도하고 응답 오류 본문·인증 헤더를 로그에 남기지 않는다."""
        if query is not None and not query.lstrip().startswith("query "):
            raise CollectionError("READ_ONLY", "이 수집기는 GraphQL query만 허용합니다.")
        url = self.checked_url(url, graphql=query is not None)
        body = (
            json.dumps({"query": query, "variables": variables or {}}).encode() if query else None
        )
        for attempt in range(self.config.max_retries + 1):
            self.check()
            if self.requests >= self.config.max_requests_per_run:
                raise CollectionError(
                    "REQUEST_BUDGET_EXCEEDED",
                    "이번 실행의 요청 상한에 도달했습니다. 남은 작업을 보존합니다.",
                )
            if self.consecutive_rate_limits >= self.config.max_consecutive_rate_limits:
                raise CollectionError(
                    "RATE_LIMIT_CIRCUIT_OPEN",
                    "연속 429 응답으로 이번 수집을 중단합니다. 제한 해제 후 재개하세요.",
                    429,
                )
            # Every attempt needs both permits; the worker's cancellation checks remain active.
            user_details = query is None and re.fullmatch(r"/api/v4/users/[0-9]+/?", urlsplit(url).path)
            self.bucket.acquire(*((self.user_details_bucket,) if user_details else ()))
            self.check()
            request = Request(
                url,
                data=body,
                method="POST" if query else "GET",
                headers={
                    "PRIVATE-TOKEN": self.token,
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                    "User-Agent": f"gitlab-metadata-inventory/{__version__}",
                },
            )
            wait = 0.0
            self.requests += 1
            try:
                with self.opener.open(request, timeout=self.config.timeout_seconds) as response:
                    headers = {k.lower(): v for k, v in response.headers.items()}
                    self.consecutive_rate_limits = 0
                    length = headers.get("content-length", "")
                    if length.isdecimal() and int(length) > self.config.max_response_bytes:
                        raise CollectionError(
                            "RESPONSE_TOO_LARGE", "API 응답이 설정한 크기 상한을 초과했습니다."
                        )
                    raw = response.read(self.config.max_response_bytes + 1)
                    if len(raw) > self.config.max_response_bytes:
                        raise CollectionError(
                            "RESPONSE_TOO_LARGE", "API 응답이 설정한 크기 상한을 초과했습니다."
                        )
                    # 잘못된 HTML 응답도 빈 목록으로 바꾸지 않고 명시적으로 실패시킨다.
                    try:
                        return Response(json.loads(raw), headers)
                    except (ValueError, UnicodeDecodeError) as exc:
                        raise CollectionError(
                            "INVALID_JSON", "API 응답이 유효한 JSON이 아닙니다."
                        ) from exc
            except HTTPError as exc:
                status = exc.code
                headers = {key.lower(): value for key, value in exc.headers.items()}
                wait = retry_after(headers.get("retry-after"))
                if status == 429:
                    wait = max(
                        wait,
                        rate_limit_reset(headers.get("ratelimit-reset")),
                        retry_after(headers.get("ratelimit-resettime")),
                    )
                    self.consecutive_rate_limits += 1
                else:
                    self.consecutive_rate_limits = 0
                exc.close()
                code = {
                    401: "AUTHENTICATION_FAILED",
                    403: "FORBIDDEN",
                    404: "UNAVAILABLE_OR_NOT_VISIBLE",
                    429: "RATE_LIMITED",
                }.get(status, "HTTP_ERROR")
                failure = CollectionError(
                    code, f"HTTP {status}: 수집 범위·권한·기능 제공 여부를 확인하세요.", status
                )
                if status not in (429, 500, 502, 503, 504):
                    raise failure from None
                if (
                    status == 429
                    and self.consecutive_rate_limits >= self.config.max_consecutive_rate_limits
                ):
                    raise CollectionError(
                        "RATE_LIMIT_CIRCUIT_OPEN",
                        "연속 429 응답으로 이번 수집을 중단합니다. 제한 해제 후 재개하세요.",
                        429,
                        {
                            "consecutive_429": self.consecutive_rate_limits,
                            "retry_after_seconds": wait,
                        },
                    ) from None
            except (URLError, TimeoutError, OSError) as exc:
                reason = getattr(exc, "reason", exc)
                if isinstance(reason, ssl.SSLCertVerificationError):
                    raise CollectionError(
                        "TLS_VERIFICATION_FAILED",
                        "인증서 신뢰 검증에 실패했습니다. TLS 검증을 끄지 말고 연결 설정을 확인하세요.",
                    ) from None
                failure = CollectionError(
                    "NETWORK_ERROR", "연결 또는 응답 대기 중 오류가 발생했습니다."
                )
            # 긴 서버 대기 요구를 무시해 재요청하지 않는다. 작업을 남겨 나중에 재개한다.
            if wait > 60:
                raise CollectionError(
                    "RETRY_LATER",
                    f"서버가 {int(wait)}초 대기를 요구했습니다. 이후 --resume으로 재개하세요.",
                    failure.status,
                    {"retry_after_seconds": wait},
                )
            if attempt == self.config.max_retries:
                raise failure
            delay = max(
                wait,
                random.uniform(
                    self.config.retry_min_seconds,
                    max(self.config.retry_min_seconds, min(30, 2**attempt)),
                ),
            )
            LOG.warning(
                "stage=http_retry code=%s attempt=%s delay=%.2f path=%s",
                failure.code,
                attempt + 1,
                delay,
                urlsplit(url).path,
            )
            self.retries += 1
            self.sleep(delay)
        raise AssertionError("unreachable")


def next_page(client: Client, url: str, headers: dict, count: int, page_size: int) -> str | None:
    """서버 Link/X-Next-Page를 우선 사용하고, 헤더 부재 시 offset을 보수적으로 진행한다."""
    for target, relation in re.findall(
        r'<([^>]+)>\s*;\s*rel="?([^";, ]+)"?', headers.get("link", "")
    ):
        if relation == "next":
            return client.checked_url(urljoin(url, target))
    parts = urlsplit(url)
    params = dict(parse_qsl(parts.query))
    if params.get("pagination") == "keyset":
        # Keyset API는 다음 Link의 부재가 종료다. 임의 offset/cursor를 만들지 않는다.
        return None
    if "x-next-page" in headers:
        following = headers["x-next-page"]
        if not following:
            return None
        if not following.isdecimal() or int(following) < 1:
            raise CollectionError(
                "INVALID_PAGINATION", "X-Next-Page가 유효한 페이지 번호가 아닙니다."
            )
        params["page"] = following
    elif count < page_size:
        return None
    else:
        # 총 건수 헤더는 GitLab.com에서 생략될 수 있어 종료 조건으로 쓰지 않는다.
        params["page"] = str(int(params.get("page", "1")) + 1)
    return client.checked_url(
        urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(params), ""))
    )
