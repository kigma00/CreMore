"""CODEOWNERS as GitHub and GitLab read it: the owners a path has. Pure; no I/O.

The last pattern that matches a path decides its owners; a matching pattern with no owners leaves the
path unowned (GitHub). GitLab reads the file in ``[Section]`` blocks (``^[Section]`` for an optional one):
each section's last match applies, and an entry without owners takes its section's default owners.
Patterns follow gitignore: a leading ``/`` anchors to the repository root, as does a ``/`` in the
middle; a trailing ``/`` names a directory and everything under it; ``*`` and ``?`` do not cross ``/``;
``**`` does. Owners are ``@user``, ``@org/team`` (a GitLab ``@group/subgroup``), ``@@role`` (GitLab)
or an email address. ``#`` starts a comment; ``\\ `` and ``\\#`` escape a space and a hash.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Where each host looks, in its order: the first file found is the one it uses.
LOCATIONS = {"github": (".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"),
             "gitlab": ("CODEOWNERS", "docs/CODEOWNERS", ".gitlab/CODEOWNERS")}
MAX_BYTES = 3 * 1024 * 1024  # GitHub ignores a larger file
MAX_RULES = 10000
_OWNER = re.compile(r"@@[A-Za-z_]{1,40}|@[A-Za-z0-9_.-]{1,100}(?:/[A-Za-z0-9_.-]{1,100}){0,20}|[^@\s]{1,200}@[^@\s]{1,200}\.[^@\s]{1,40}")
_SECTION = re.compile(r"\^?\[([^\]]{1,200})\](?:\[\d{1,4}\])?(?:\s+(.*))?")


@dataclass(frozen=True)
class Rule:
    pattern: str
    owners: tuple[str, ...]
    line: int
    section: str
    regex: re.Pattern


def _tokens(line: str) -> list[str]:
    """Whitespace-split with ``\\ `` and ``\\#`` kept literal; an unescaped ``#`` ends the line."""
    out, current, escaped = [], "", False
    for char in line:
        if escaped:
            current, escaped = current + char, False
        elif char == "\\":
            escaped = True
        elif char == "#":
            break
        elif char.isspace():
            if current:
                out.append(current)
            current = ""
        else:
            current += char
    if current:
        out.append(current)
    return out


def _regex(pattern: str) -> re.Pattern | None:
    directory = pattern.endswith("/")
    body = pattern.rstrip("/")
    if not body or body == "/":
        return None
    anchored = body.startswith("/") or "/" in body.strip("/")
    body = body.lstrip("/")
    out, index = "", 0
    while index < len(body):
        if body.startswith("**/", index):
            out, index = out + "(?:.*/)?", index + 3
        elif body.startswith("/**", index) and index + 3 == len(body):
            out, index = out + "/.*", index + 3
        elif body.startswith("**", index):
            out, index = out + ".*", index + 2
        elif body[index] == "*":
            out, index = out + "[^/]*", index + 1
        elif body[index] == "?":
            out, index = out + "[^/]", index + 1
        else:
            out, index = out + re.escape(body[index]), index + 1
    prefix = "" if anchored else "(?:.*/)?"
    # A directory pattern owns what is under it; any other also names a directory of that name,
    # except "dir/*", which GitHub documents as the files directly in dir.
    suffix = "/.*" if directory else "" if body.endswith("/*") else "(?:/.*)?"
    return re.compile(prefix + out + suffix)


def owner_kind(owner: str) -> str:
    if owner.startswith("@@"):
        return "role"
    if owner.startswith("@"):
        return "team" if "/" in owner else "account"
    return "email"


def parse(text: str) -> list[Rule]:
    """The file's rules, in order; lines that are not a rule (comments, blanks, malformed) are skipped."""
    rules, section, defaults = [], "", ()
    for number, raw in enumerate(text[:MAX_BYTES].splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        header = _SECTION.fullmatch(line)
        if header:
            section = header.group(1).strip().lower()
            defaults = tuple(token for token in _tokens(header.group(2) or "") if _OWNER.fullmatch(token))
            continue
        tokens = _tokens(line)
        if not tokens:
            continue
        pattern, owners = tokens[0], tuple(token for token in tokens[1:] if _OWNER.fullmatch(token))
        regex = _regex(pattern)
        if regex is None:
            continue
        rules.append(Rule(pattern, owners or (defaults if section else ()), number, section, regex))
        if len(rules) >= MAX_RULES:
            break
    return rules


def owners_for(rules: list[Rule], path: str) -> list[dict]:
    """``[{owner, kind, line, section, pattern}]`` for ``path``: each section's last matching rule."""
    path = path.lstrip("/")
    last: dict[str, Rule] = {}
    for rule in rules:
        if rule.regex.fullmatch(path):
            last[rule.section] = rule
    out, seen = [], set()
    for rule in sorted(last.values(), key=lambda rule: rule.line):
        for owner in rule.owners:
            if owner.lower() not in seen:
                seen.add(owner.lower())
                out.append({"owner": owner, "kind": owner_kind(owner), "line": rule.line, "section": rule.section,
                            "pattern": rule.pattern})
    return out
