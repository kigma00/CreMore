import json

from cremore_github_provider.collectors.github_secret_scanning import (
    PER_PAGE,
    collect,
    run,
    unavailable,
)

SECRET = "ghp_" + "0" * 36
BASE = "https://api.github.com"


class FakeResponse:
    """A streamed response, the shape bounded_request reads."""

    encoding = "utf-8"

    def __init__(self, status, body):
        self.status_code, self.headers = status, {}
        self.content = json.dumps(body).encode()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return None

    def iter_bytes(self, chunk_size=None):
        yield self.content


class FakeGitHub:
    """Answers each requested URL in order; records what was asked for."""

    def __init__(self, *pages):
        self.pages, self.urls = list(pages), []

    def stream(self, method, url, **kwargs):
        assert method == "GET", "secret-scanning reads are read-only"
        self.urls.append(url)
        status, body = self.pages.pop(0) if self.pages else (200, [])
        return FakeResponse(status, body)


def alert(number, **overrides):
    return {"number": number, "created_at": "2026-09-01T00:00:00Z", "updated_at": "2026-09-02T00:00:00Z",
            "state": "open", "resolution": None, "secret_type": "github_personal_access_token",
            "secret_type_display_name": "GitHub Personal Access Token", "validity": "active",
            "publicly_leaked": False, "multi_repo": False, "push_protection_bypassed": False,
            "html_url": "https://github.com/org/app/security/secret-scanning/1",
            # Everything below must not survive the reduction.
            "secret": SECRET, "url": f"{BASE}/repos/org/app/secret-scanning/alerts/{number}",
            "locations_url": f"{BASE}/repos/org/app/secret-scanning/alerts/{number}/locations",
            "resolved_by": {"login": "someone", "id": 42, "email": "someone@example.test"},
            **overrides}


def test_the_raw_secret_never_leaves_the_reader():
    client = FakeGitHub((200, [alert(1), alert(2, state="resolved", resolution="revoked", validity="inactive")]))
    result = collect(client, {"Authorization": "Bearer synthetic-connection"}, base_url=BASE, repository="org/app")
    body = json.dumps(result)
    assert SECRET not in body and "locations_url" not in body and "resolved_by" not in body
    assert "someone@example.test" not in body and "secret" not in result["alerts"][0]
    assert result["collection_status"] == "COMPLETE" and result["counts"]["alerts"] == 2
    assert result["counts"] == {"alerts": 2, "open": 1, "resolved": 1, "validity_active": 1,
                                "publicly_leaked": 0, "push_protection_bypassed": 0}
    # The metadata that makes the alert useful is kept, including GitHub's own link.
    first = result["alerts"][0]
    assert first["secret_type"] == "github_personal_access_token" and first["validity"] == "active"
    assert first["html_url"].startswith("https://github.com/") and first["repository"] == "org/app"


def test_alert_metadata_is_screened_against_value_and_connection_credential():
    value, token = "synthetic-alert-value", "synthetic-connection-credential"
    row = alert(1, secret=value, repository={"full_name": value}, secret_type_display_name=value,
                resolution=token, html_url="https://github.com/org/app?value=" + value)
    result = collect(FakeGitHub((200, [row])), {"Authorization": "Bearer " + token},
                     base_url=BASE, organization="org")
    assert value not in json.dumps(result) and token not in json.dumps(result)
    assert result["counts"]["alerts"] == 1 and result["alerts"][0]["number"] == "1"
    assert result["alerts"][0]["repository"] == "" and result["alerts"][0]["html_url"] == ""


def test_a_refusal_is_never_reported_as_a_repository_with_no_alerts():
    for status, reason in ((404, "SECRET_SCANNING_NOT_ENABLED"), (403, "NOT_AUTHORIZED")):
        result = collect(FakeGitHub((status, {"message": "nope"})), {}, base_url=BASE, repository="org/app")
        # Not COMPLETE and not zero alerts read as clean: the reason is carried.
        assert result["collection_status"] == "UNSUPPORTED" and result["reason_code"] == reason
        assert result["counts"]["alerts"] == 0 and result["limitations"]
    rejected = collect(FakeGitHub((401, {})), {}, base_url=BASE, organization="org")
    assert rejected["collection_status"] == "FAILED" and rejected["reason_code"] == "CREDENTIAL_REJECTED"
    # A refusal after a page was read keeps what was read and says it is partial.
    partial = collect(FakeGitHub((200, [alert(n) for n in range(PER_PAGE)]), (403, {})),
                      {}, base_url=BASE, organization="org")
    assert partial["collection_status"] == "PARTIAL" and partial["counts"]["alerts"] == PER_PAGE
    assert partial["reason_code"] == "NOT_AUTHORIZED"


def test_organisation_reads_page_until_short_and_records_each_alert_repository():
    pages = [(200, [alert(n, repository={"full_name": "org/app"}) for n in range(PER_PAGE)]),
             (200, [alert(999, repository={"full_name": "org/other"}, publicly_leaked=True,
                          push_protection_bypassed=True)])]
    client = FakeGitHub(*pages)
    result = collect(client, {}, base_url=BASE, organization="org")
    assert result["collection_status"] == "COMPLETE" and result["scope"] == "ORGANIZATION"
    assert [url.split("page=")[-1] for url in client.urls] == ["1", "2"]
    assert result["alerts"][-1]["repository"] == "org/other"
    assert result["counts"]["publicly_leaked"] == 1 and result["counts"]["push_protection_bypassed"] == 1
    # The page limit is reported rather than silently truncating a complete read.
    capped = collect(FakeGitHub(*[(200, [alert(n) for n in range(PER_PAGE)])] * 2),
                     {}, base_url=BASE, organization="org", max_pages=2)
    assert capped["collection_status"] == "PARTIAL" and capped["truncated"] and capped["reason_code"] == "PAGE_LIMIT_REACHED"


def test_one_target_only_and_unknown_provider_values_are_not_guessed():
    for kwargs in ({}, {"organization": "org", "repository": "org/app"}):
        try:
            collect(FakeGitHub(), {}, base_url=BASE, **kwargs)
        except ValueError as exc:
            assert "exactly one" in str(exc)
        else:
            raise AssertionError("expected a refusal")
    odd = collect(FakeGitHub((200, [alert(1, state="dismissed", validity="probably")])),
                  {}, base_url=BASE, repository="org/app")
    assert odd["alerts"][0]["state"] == "unknown" and odd["alerts"][0]["validity"] == "unknown"


def test_run_resolves_dynamic_app_tokens_and_closes_the_owned_http_client():
    import httpx

    requests = []

    def respond(request):
        requests.append(request)
        assert request.headers["Authorization"] == "Bearer synthetic-installation-token"
        return httpx.Response(200, json=[alert(1)])

    client = httpx.Client(transport=httpx.MockTransport(respond))
    result = run({"owner": "org", "repo": "app", "token": lambda: "synthetic-installation-token"},
                 http_client_factory=lambda: client)
    assert result["collection_status"] == "COMPLETE" and client.is_closed and len(requests) == 1
    assert "synthetic-installation-token" not in json.dumps(result)


def test_an_unusable_resolved_credential_is_recorded_not_sent():
    """The worker resolved the reference; a malformed credential is recorded without a request."""
    requests = []
    result = run({"owner": "org", "repo": "app", "token": "not a token"},
                 http_client_factory=lambda: requests.append(1))
    assert result == {**unavailable({"owner": "org", "repo": "app"}), "collected_at": result["collected_at"]}
    assert result["reason_code"] == "SECRET_UNAVAILABLE" and requests == []


def test_skipped_malformed_alerts_are_partial_evidence():
    result = collect(FakeGitHub((200, [None, alert(1)])), {}, base_url=BASE, repository="org/app")
    assert result["collection_status"] == "PARTIAL" and result["counts"]["alerts"] == 1


def test_alert_pages_are_bounded_before_projection_and_results_share_a_budget(monkeypatch):
    from cremore_github_provider.collectors import github_secret_scanning as module

    monkeypatch.setattr(module, "PER_PAGE", 2)
    client = FakeGitHub((200, [alert(1), alert(2), alert(3)]))
    oversized = collect(client, {}, base_url=BASE, repository="org/app")
    assert oversized["alerts"] == [] and oversized["truncated"]
    assert oversized["reason_code"] == "RESPONSE_PAGE_LIMIT_EXCEEDED"
    monkeypatch.setattr(module, "MAX_PAGES", 2)
    client = FakeGitHub(*[(200, [alert(1), alert(2)])] * 3)
    limited = collect(client, {}, base_url=BASE, repository="org/app", max_pages=100)
    assert limited["collection_status"] == "PARTIAL" and len(client.urls) == 2
    monkeypatch.setattr(module, "MAX_RESULT_BYTES", len(json.dumps(module._alert(alert(1), "org/app"))) + 3)
    result = collect(FakeGitHub((200, [alert(1), alert(2)])), {}, base_url=BASE, repository="org/app")
    assert result["counts"]["alerts"] == 1 and result["truncated"]
    assert result["reason_code"] == "ALERT_RESULT_LIMIT_EXCEEDED"
