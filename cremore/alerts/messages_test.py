"""What a Slack detection alert says, in Korean and English, standard and minimal: the details a security team acts
on, plain text that can neither format nor mention nor link, and a console link only when the console's address is
known."""

import datetime as dt
import json
import uuid

from cremore.alerts import messages

CREDENTIAL, EVENT = str(uuid.uuid4()), str(uuid.uuid4())
LINK = f"https://cremore.example.com/?view=exposed&id=credential%3A{CREDENTIAL}"


def item(**changes):
    return {"kind": "finding.created", "severity": "HIGH", "event_id": EVENT, "credential_id": CREDENTIAL,
            "provider": "aws", "credential_type": "AWS_ACCESS_KEY", "status": "Active", "source_type": "github",
            "connection": "Payments GitHub", "resource": "acme/payments", "location": "config/settings.py", "line": 42,
            "first_seen": dt.datetime(2026, 10, 9, 5, 3, tzinfo=dt.UTC), "trigger": "SCHEDULE", "others": 2,
            "link": LINK, **changes}


def texts(payload) -> list[str]:
    """Every text a reader can see, block by block."""
    out = [payload["text"]]
    for block in payload["blocks"]:
        out += [block[key]["text"] for key in ("text",) if key in block]
        out += [element["text"]["text"] if element["type"] == "button" else element["text"]
                for element in block.get("elements", [])]
        out += [block["accessory"]["text"]["text"]] if "accessory" in block else []
    return out


def plain_only(payload) -> bool:
    found = []

    def walk(value):
        if isinstance(value, dict):
            if "type" in value and value["type"] in ("plain_text", "mrkdwn"):
                found.append(value["type"])
            for inner in value.values():
                walk(inner)
        elif isinstance(value, list):
            for inner in value:
                walk(inner)
    walk(payload["blocks"])
    return set(found) == {"plain_text"}


def test_a_standard_korean_alert_names_everything_a_security_team_acts_on():
    payload = messages.render([item()], detail="standard", language="ko")
    header, section, actions, context = payload["blocks"]
    assert header == {"type": "header", "text": {"type": "plain_text", "text": "[높음] 새 자격증명 노출", "emoji": False}}
    assert section["text"]["text"].split("\n") == [
        "유형: AWS access key pair · 발급: aws", "검증: 활성 확인", "발견 위치: GitHub · Payments GitHub",
        "리소스: acme/payments", "위치: config/settings.py (42행)", "처음 발견: 2026-10-09 14:03 KST", "검사 시작: 예약",
        "다른 열린 위치: 2곳", "콘솔: " + LINK.replace("&", "&amp;")]
    # The button opens the credential in the console; the address is also there as text to copy.
    assert actions["elements"] == [{"type": "button", "text": {"type": "plain_text", "text": "콘솔에서 열기", "emoji": False},
                                    "url": LINK, "action_id": "open_finding"}]
    assert context["elements"][0]["text"] == f"Credential ID {CREDENTIAL} · 이벤트 {EVENT}"
    assert payload["text"].startswith("[높음] 새 자격증명 노출 · 유형: AWS access key pair")
    # Nothing formats, mentions, links or unfurls.
    assert {key: payload[key] for key in ("mrkdwn", "parse", "link_names", "unfurl_links", "unfurl_media")} == {
        "mrkdwn": False, "parse": "none", "link_names": False, "unfurl_links": False, "unfurl_media": False}
    assert plain_only(payload)


def test_english_reads_utc_and_each_event_type_and_state_has_its_words():
    payload = messages.render([item(kind="finding.location_added", severity="CRITICAL", status="UNKNOWN", trigger="EVENT",
                                    others=0, line=None)], detail="standard", language="en")
    header, section = payload["blocks"][0]["text"]["text"], payload["blocks"][1]["text"]["text"].split("\n")
    assert header == "[Critical] Found at a new location"
    assert "Verification: Not verified" in section and "First seen: 2026-10-09 05:03 UTC" in section
    assert "Location: config/settings.py" in section and "Scan started by: Change event" in section
    assert "Other open locations: 0" in section and section[0] == "Type: AWS access key pair · Issuer: aws"
    assert messages.render([item(kind="finding.reappeared", severity="UNKNOWN", status="Revoked")], detail="standard",
                           language="en")["blocks"][0]["text"]["text"] == "[Unknown] Exposure reappeared"
    # A trigger the job did not record, and a resource that is its location, are left out rather than guessed.
    lines = messages.render([item(trigger=None, resource="config/settings.py")], detail="standard", language="en")
    assert not any(line.startswith(("Scan started by", "Resource")) for line in lines["blocks"][1]["text"]["text"].split("\n"))


def test_a_change_event_says_whether_a_feed_a_queue_or_a_webhook_reported_it():
    def started(language, **changes):
        text = messages.render([item(**changes)], detail="standard", language=language)["blocks"][1]["text"]["text"]
        return next(line for line in text.split("\n") if line.startswith(("검사 시작", "Scan started by")))

    for origin, ko, en in (("feed", "피드", "feed"), ("queue", "큐", "queue"), ("webhook", "웹훅", "webhook")):
        assert started("ko", trigger="EVENT", origin=origin) == f"검사 시작: 변경 알림({ko})"
        assert started("en", trigger="EVENT", origin=origin) == f"Scan started by: Change event ({en})"
    # An older run did not record where its event came from; another trigger has no origin to name.
    assert started("ko", trigger="EVENT", origin="event") == started("ko", trigger="EVENT") == "검사 시작: 변경 알림"
    assert started("en", trigger="SCHEDULE", origin="feed") == "Scan started by: Scheduled"
    assert "피드" not in json.dumps(messages.render([item(trigger="EVENT", origin="feed")], detail="minimal", language="ko"),
                                   ensure_ascii=False)


def test_minimal_carries_severity_type_source_and_the_link_only():
    payload = messages.render([item()], detail="minimal", language="ko")
    assert payload["blocks"][0]["text"]["text"] == "[높음] 새 자격증명 노출"
    assert payload["blocks"][1]["text"]["text"].split("\n") == ["AWS access key pair · GitHub", "콘솔: " + LINK.replace("&", "&amp;")]
    seen = " ".join(texts(payload))
    for detail in ("acme/payments", "config/settings.py", "Payments GitHub", "활성 확인", "예약", "KST"):
        assert detail not in seen, detail
    assert payload["blocks"][2]["elements"][0]["url"] == LINK
    # The short form retried after a refusal: the link stays as text, with no button Slack could refuse.
    short = messages.render([item()], detail="minimal", language="ko", buttons=False)
    assert [block["type"] for block in short["blocks"]] == ["header", "section", "context"]
    assert short["blocks"][1] == payload["blocks"][1]


SOURCES = [{"address": "203.0.113.5", "kind": "IPV4", "last_seen_at": "2026-10-04T05:03:00+00:00", "count": 3},
           {"address": "cloudtrail.amazonaws.com", "kind": "AWS_INTERNAL", "last_seen_at": "2026-10-03T05:03:00+00:00", "count": 1},
           {"address": "198.51.100.7", "kind": "IPV4", "last_seen_at": None, "count": 1},
           {"address": "192.0.2.1", "kind": "IPV4", "last_seen_at": "2026-10-01T05:03:00+00:00", "count": 1},
           {"address": "192.0.2.2", "kind": "IPV4", "last_seen_at": "2026-10-01T05:03:00+00:00", "count": 1}]


def test_a_standard_alert_names_three_recent_source_addresses_with_their_times_and_counts_the_rest():
    def line(language, **changes):
        text = messages.render([item(**changes)], detail="standard", language=language)["blocks"][1]["text"]["text"]
        return next(row for row in text.split("\n") if row.startswith(("최근 사용 출처", "Recently used from")))

    # Delivery passes the newest three and how many distinct addresses the lookup saw in all its events.
    assert line("ko", sources=SOURCES[:3], sources_total=40) == (
        "최근 사용 출처: 203.0.113.5 (2026-10-04 14:03 KST), AWS 서비스 cloudtrail.amazonaws.com (2026-10-03 14:03 KST), "
        "198.51.100.7 +37")
    assert line("en", sources=SOURCES[:2], sources_total=2) == (
        "Recently used from: 203.0.113.5 (2026-10-04 05:03 UTC), AWS service cloudtrail.amazonaws.com (2026-10-03 05:03 UTC)")
    # Addresses past what the lookup could count: the total is a lower bound.
    assert line("ko", sources=SOURCES[:3], sources_total=1256, sources_more=True).endswith("198.51.100.7 +1,253 이상")
    assert line("en", sources=SOURCES[:3], sources_total=256, sources_more=True).endswith("198.51.100.7 +253+")
    # A lower bound with none known past those shown: a hint with no number, never "+0".
    for language, hint in (("ko", "(2026-10-04 14:03 KST), 더 있을 수 있음"), ("en", "(2026-10-04 05:03 UTC), possibly more")):
        text = line(language, sources=SOURCES[:1], sources_total=1, sources_more=True)
        assert text.endswith(hint) and "+0" not in text
    # No lookup, no line; minimal never names an address.
    assert not any("최근 사용 출처" in row for row in
                   messages.render([item()], detail="standard", language="ko")["blocks"][1]["text"]["text"].split("\n"))
    assert "203.0.113.5" not in " ".join(texts(messages.render([item(sources=SOURCES)], detail="minimal", language="ko")))
    # An address from the lookup is plain text like every other name.
    hostile = [{"address": "<!channel> *x*\u202e", "kind": "HOSTNAME", "last_seen_at": None, "count": 1}]
    text = messages.render([item(sources=hostile)], detail="standard", language="en")["blocks"][1]["text"]["text"]
    assert "<!channel>" not in text and "&lt;!channel&gt;" in text and "\u202e" not in text


def test_a_count_from_the_first_rows_only_says_there_are_more():
    for language, line in (("ko", "다른 열린 위치: 1,000곳 이상"), ("en", "Other open locations: 1,000+")):
        payload = messages.render([item(others=1000, others_more=True)], detail="standard", language=language)
        assert payload["blocks"][1]["text"]["text"].split("\n")[-2] == line
    # A digest without buttons carries each link as text only.
    digest = messages.render([item(), item(event_id=str(uuid.uuid4()))], detail="standard", language="en", buttons=False)
    assert all("accessory" not in block for block in digest["blocks"]) and LINK.replace("&", "&amp;") in json.dumps(digest)


def test_without_a_console_address_the_alert_still_goes_out_with_its_ids():
    payload = messages.render([item(link=None)], detail="standard", language="en")
    assert [block["type"] for block in payload["blocks"]] == ["header", "section", "context"]
    assert "Console" not in payload["blocks"][1]["text"]["text"]
    assert payload["blocks"][2]["elements"][0]["text"] == f"Credential ID {CREDENTIAL} · Event {EVENT}"


def test_names_and_paths_are_text_never_formatting_mentions_or_links():
    rlo, pdf = chr(0x202E), chr(0x202C)  # a right-to-left override and its end
    hostile = f"<!channel> *bold* _it_ `code` <https://evil.example|click> & {rlo}doc{pdf}" + chr(10) + "next"
    payload = messages.render([item(resource=hostile, connection="<@U123> team", location="docs/" + hostile)],
                              detail="standard", language="en")
    section = payload["blocks"][1]["text"]["text"]
    assert "<" not in section.replace("&lt;", "") and ">" not in section.replace("&gt;", "")
    assert "&lt;!channel&gt;" in section and "&lt;@U123&gt; team" in section and "&amp; " in section
    assert rlo not in section and pdf not in section and section.count(chr(10)) == 8  # no line of its own
    assert plain_only(payload)
    # A URL location keeps its scheme, host and path: a query, fragment or user info can hold a token.
    shown = messages.render([item(location="https://user:pw@docs.example.com:8443/page/1?token=s3cr3t#frag",
                                  source_type="website")], detail="standard", language="en")["blocks"][1]["text"]["text"]
    assert "Location: https://docs.example.com:8443/page/1 (line 42)" in shown
    assert all(word not in shown for word in ("s3cr3t", "token=", "frag", "user", "pw@"))


def test_long_values_are_bounded_within_slack_limits():
    payload = messages.render([item(resource="r" * 5000, location="&" * 5000, connection="c" * 900)], detail="standard",
                              language="ko")
    section = payload["blocks"][1]["text"]["text"]
    assert len(section) <= messages.TEXT_MAX and "r" * 200 not in section and "c" * 100 not in section
    assert not section.endswith(("&", "&a", "&am", "&amp")) and "…" in section
    assert len(payload["text"]) <= messages.TEXT_MAX


def test_a_digest_lists_each_alert_with_its_own_button():
    items = [item(event_id=str(uuid.uuid4()), credential_id=str(uuid.uuid4()), severity=level)
             for level in ("CRITICAL", "HIGH", "LOW", "INFO")]
    items[3]["link"] = None
    payload = messages.render(items, detail="standard", language="ko")
    header, *sections = payload["blocks"]
    assert header["text"]["text"] == payload["text"] == "CreMore 새 탐지 4건"
    assert len(sections) == 4 and [s["text"]["text"].split("\n")[0] for s in sections] == [
        "[심각] 새 자격증명 노출", "[높음] 새 자격증명 노출", "[낮음] 새 자격증명 노출", "[정보] 새 자격증명 노출"]
    assert [s["accessory"]["action_id"] for s in sections[:3]] == ["open_finding_0", "open_finding_1", "open_finding_2"]
    assert "accessory" not in sections[3] and f"Credential ID {items[3]['credential_id']}" in sections[3]["text"]["text"]
    # Each item names its event, so a repeated delivery can be told apart.
    assert [s["text"]["text"].split("\n")[-1] for s in sections] == [f"이벤트 {item['event_id']}" for item in items]
    assert all(len(s["text"]["text"]) <= messages.TEXT_MAX for s in sections) and len(payload["blocks"]) <= 50
    minimal = messages.render(items, detail="minimal", language="en")
    assert minimal["blocks"][1]["text"]["text"].split("\n")[:2] == ["[Critical] New credential exposure", "AWS access key pair · GitHub"]


def test_a_digest_of_long_names_stays_well_under_slack_limits():
    long = item(connection="C" * 100, resource="org/" + "r&" * 98, location="src/" + "d&/" * 165)
    payload = messages.render([dict(long, event_id=str(uuid.uuid4())) for _ in range(15)], detail="standard", language="ko")
    text = sum(len(block["text"]["text"]) for block in payload["blocks"])
    assert text < 8000 and len(json.dumps(payload, ensure_ascii=False).encode()) < 16 * 1024
    # Past the budget the items keep their title, type, source, link and IDs in the short form.
    short = payload["blocks"][-1]["text"]["text"].split("\n")
    assert short[0] == "[높음] 새 자격증명 노출" and short[1] == "AWS access key pair · GitHub" and short[-1].startswith("이벤트 ")


def test_a_rise_to_the_minimum_says_from_what_to_what():
    payload = messages.render([item(kind="finding.severity_raised", severity="CRITICAL", previous_severity="LOW")],
                              detail="standard", language="en")
    assert payload["blocks"][0]["text"]["text"] == "[Critical] Severity raised"
    assert payload["blocks"][1]["text"]["text"].split("\n")[0] == "Severity: Low → Critical"


def test_a_name_shaped_like_a_credential_is_replaced_and_a_bad_port_still_loses_user_info():
    token = "ghp_" + "aB3dE5fG7hJ9kL1mN2pQ4rS6tU8vW0xY2zC4"  # synthetic, built at run time
    payload = messages.render([item(resource=f"acme/{token}", connection=f"team {token}",
                                    location=f"config/{token}.txt")], detail="standard", language="en")
    section = payload["blocks"][1]["text"]["text"]
    assert token not in json.dumps(payload) and section.count("(not shown · see the console)") == 3
    assert messages._place("https://user:s3cret@docs.example.com:99999/p?x=1#f") == "https://docs.example.com:99999/p"
    assert messages._place("ftp://u@files.example.com/a b?c") == "ftp://files.example.com/a b"
    assert messages._place("plain/path?not-a-url") == "plain/path?not-a-url"


def test_type_names_come_from_the_detector_catalog():
    assert messages._type({"provider": "github", "credential_type": "GITHUB_TOKEN"}, lambda ko, en: en) == "GitHub token"
    assert messages._type({"provider": "acme", "credential_type": "ACME_API_KEY"}, lambda ko, en: en) == "Acme Api Key"
    assert messages._type({"provider": "custom", "credential_type": "ANYTHING"}, lambda ko, en: ko) == "사용자 규칙 일치"


def test_the_test_message_says_where_alerts_arrive():
    payload = messages.trial_message("https://cremore.example.com", language="ko")
    assert payload["blocks"][0]["text"]["text"] == "CreMore Slack 탐지 알림 시험"
    assert payload["blocks"][2]["elements"][0]["url"] == "https://cremore.example.com/"
    bare = messages.trial_message(None, language="en")
    assert [block["type"] for block in bare["blocks"]] == ["header", "section"]
    assert "secret value" in json.dumps(bare) and plain_only(bare)
