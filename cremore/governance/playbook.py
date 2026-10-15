"""The remediation playbook an exposure-response request carries.

It is the console's own guide (web/console/views/credentials/guides.json, copied next to this module; a test keeps the
two equal) as plain text in ko or en. The issuing service picks the revocation guide, the kinds of place the credential
is still exposed at pick the clean-up steps, and every request ends with moving the new value into a vault. Like the
rest of the request it never names a value, snippet, location or person: ``{name}`` and ``{issuer}`` become fixed words
and ``{hint}`` the masked identifier the message already shows.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

GUIDES = json.loads(Path(__file__).with_name("remediation_guides.json").read_text(encoding="utf-8"))
_MARKUP = re.compile(r"</?(?:b|code)>")
_ENDED = ("Inactive", "Revoked", "Expired")  # CredentialStatus: nothing left to revoke
_WORDS = {
    "ko": {"head": "조치 방법(플레이북)", "name": "이 자격증명", "issuer": "해당 항목", "open": "바로 가기",
           "cleanup": "노출 원본과 이력 정리", "vault": "새 값을 Vault로 옮기기"},
    "en": {"head": "How to fix it (playbook)", "name": "this credential", "issuer": "the matching entry",
           "open": "Open", "cleanup": "Clean up the source and its history", "vault": "Move the new value into Vault"},
}


def location_kind(source_type: str) -> str:
    """The console's locKind: what clean-up a place needs, by the kind of source it is in."""
    if source_type in ("github", "gitlab", "bitbucket", "azure_devops"):
        return "git"
    if source_type in ("notion", "confluence"):
        return "doc"
    return "web" if source_type == "website" else "bucket"


def sections(provider: str, status: str | None, kinds, hint: str, locale: str) -> list[dict]:
    """``[{title, steps, link}]`` in ``locale``: revoke (unless the credential already ended), clean up each kind of
    place it is still exposed at, and store the new value in a vault. ``link`` is ``[label, url]`` or None."""
    lang = locale if locale in _WORDS else "ko"
    words, index = _WORDS[lang], 0 if lang == "ko" else 1

    def text(pair):
        return _MARKUP.sub("", pair[index]).replace("{name}", words["name"]).replace(
            "{issuer}", words["issuer"]).replace("{hint}", hint)

    out = []
    if status not in _ENDED:
        guide = GUIDES["revoke"].get(provider) or GUIDES["generic"]
        link = guide.get("link")
        out.append({"title": text(guide["title"]), "steps": [text(step) for step in guide["steps"]],
                    "link": [link[index], link[2]] if link else None})
    for kind in dict.fromkeys(kinds):
        out.append({"title": words["cleanup"], "steps": [text(step) for step in GUIDES["cleanup"][kind]], "link": None})
    out.append({"title": words["vault"], "steps": [text(step) for step in GUIDES["vault"]], "link": None})
    return out


def lines(playbook: list[dict], locale: str) -> list[str]:
    """The playbook as message lines: a heading, then each section's title, numbered steps and its link on a line of
    its own (a ticket system or chat links an address it sees alone)."""
    words = _WORDS[locale if locale in _WORDS else "ko"]
    out = [words["head"]]
    for section in playbook:
        out += ["", f"■ {section['title']}", *(f"{n}. {step}" for n, step in enumerate(section["steps"], 1))]
        if section["link"]:
            out += [f"{words['open']}: {section['link'][0]}", section["link"][1]]
    return out
