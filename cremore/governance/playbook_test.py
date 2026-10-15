"""The playbook a request carries: the console's guide data, plain and fixed, chosen per issuer and kind of place."""

import json
from pathlib import Path

import pytest

from cremore.db.repository import InMemoryRepository
from cremore.domain.text import unsafe_text
from cremore.governance import playbook
from cremore.governance.response_reports import credential_types

ROOT = Path(__file__).resolve().parents[2]
ISSUERS = sorted(playbook.GUIDES["revoke"])


def test_the_server_copy_is_the_consoles_guide_data():
    web = json.loads((ROOT / "web" / "console" / "views" / "credentials" / "guides.json").read_text(encoding="utf-8"))
    assert web == playbook.GUIDES


def pairs(value):
    return isinstance(value, list) and len(value) == 2 and all(isinstance(text, str) and text for text in value)


def test_every_guide_has_the_shape_both_sides_read():
    guides = playbook.GUIDES
    for guide in [*guides["revoke"].values(), guides["generic"]]:
        assert pairs(guide["title"]) and guide["steps"] and all(pairs(step) for step in guide["steps"])
        assert guide["link"] is None or (len(guide["link"]) == 3 and guide["link"][2].startswith("https://"))
    assert set(guides["cleanup"]) == {"git", "doc", "bucket", "web"}
    assert all(pairs(step) for steps in [*guides["cleanup"].values(), guides["vault"], guides["scope"]] for step in steps)


@pytest.fixture(scope="module")
def detector():
    from cremore.scanning.orchestrator import Orchestrator

    return Orchestrator(InMemoryRepository())

@pytest.mark.parametrize("locale", ["ko", "en"])
def test_every_playbook_is_plain_safe_text_without_a_secret_shape(locale, detector):
    hook = "hook https://hooks.slack.com/services/T01" "ABCDEF/B02GHIJKL/aB3dE5fG7hJ9kL1mN2pQ4rS6"
    assert credential_types(detector, hook) == ["SLACK_WEBHOOK"]  # the detector is really reading
    for issuer in [*ISSUERS, "unknown"]:
        sections = playbook.sections(issuer, None, ["git", "doc", "bucket", "web"], "ghp_••••", locale)
        text = "\n".join(playbook.lines(sections, locale))
        assert not unsafe_text(text, newlines=True) and "<" not in text and "{" not in text, issuer
        assert credential_types(detector, text) == [], issuer
        # Every kind of place at once stays well inside one chat message.
        assert len(text) < 3500, (issuer, len(text))


def test_the_issuer_picks_the_revocation_guide_and_an_ended_credential_skips_it():
    ko = playbook.sections("aws", "Active", ["git", "git", "doc"], "AKIA••••", "ko")
    assert [s["title"] for s in ko] == ["IAM 액세스 키 비활성화 후 삭제", "노출 원본과 이력 정리", "노출 원본과 이력 정리",
                                        "새 값을 Vault로 옮기기"]
    assert ko[0]["steps"][0] == "IAM 콘솔에서 사용자 → 해당 항목 → 보안 자격 증명으로 이동합니다."
    assert ko[0]["link"] == ["AWS IAM 사용자 콘솔", "https://console.aws.amazon.com/iam/home#/users"]
    assert ko[1]["steps"][1].startswith("이력에서도 지우려면 git filter-repo")  # git first, then doc: each kind once
    assert ko[2]["steps"][0] == "페이지에서 값을 지우고 Vault 위치를 대신 적습니다."
    unknown = playbook.sections("acme-unknown", None, [], "••••", "en")
    assert unknown[0]["title"] == "Revoke and reissue it at the issuer"
    assert unknown[0]["steps"][0] == "In the issuing service's admin console, revoke this credential or change its password."
    assert [s["title"] for s in playbook.sections("aws", "Revoked", [], "••••", "en")] == ["Move the new value into Vault"]
    # The masked identifier is the only value a step names.
    assert "kim-••••" in playbook.sections("sendgrid", None, [], "kim-••••", "en")[0]["steps"][0]


def test_lines_put_each_link_on_a_line_of_its_own():
    text = playbook.lines(playbook.sections("github", None, ["git"], "ghp_••••", "en"), "en")
    assert text[0] == "How to fix it (playbook)" and "■ Delete and reissue the token in GitHub" in text
    assert text[text.index("Open: GitHub token settings") + 1] == "https://github.com/settings/tokens"
    assert "1. Sign in as the account that created the token and open Settings → Developer settings → Personal access tokens." in text
