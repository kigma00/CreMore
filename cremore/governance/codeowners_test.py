"""CODEOWNERS the way GitHub and GitLab document it: patterns, last match, sections and owners."""

import pytest

from cremore.governance import codeowners

GITHUB = """
# Global owners
*       @global-owner1 @global-owner2
*.js    @js-owner #This is an inline comment.
*.go docs@example.com
*.txt @octo-org/octocats
/build/logs/ @doctocat
docs/*  docs@example.com
apps/ @octocat
/docs/ @doctocat
/scripts/ @doctocat @octocat
**/logs @octocat
/apps/ @octocat
/apps/github
path\\ with\\ spaces/ @spacey
"""


def owners(rules, path):
    return [item["owner"] for item in codeowners.owners_for(rules, path)]


@pytest.mark.parametrize("path, expected", [
    ("README.md", ["@global-owner1", "@global-owner2"]),
    ("src/app.js", ["@js-owner"]),
    ("main.go", ["docs@example.com"]),
    ("notes/todo.txt", ["@octo-org/octocats"]),
    ("build/logs/today.log", ["@octocat"]),         # the later **/logs wins over /build/logs/
    ("docs/getting-started.md", ["@doctocat"]),     # the later /docs/ wins over docs/*
    ("x/docs/getting-started.md", ["@global-owner1", "@global-owner2"]),  # docs/* is anchored at the root
    ("scripts/deploy.sh", ["@doctocat", "@octocat"]),
    ("deeply/nested/logs/a.txt", ["@octocat"]),
    ("apps/web/index.ts", ["@octocat"]),
    ("apps/github/readme.md", []),                  # a pattern with no owners leaves it unowned
    ("path with spaces/file", ["@spacey"]),
])
def test_github_patterns_and_the_last_match(path, expected):
    assert owners(codeowners.parse(GITHUB), path) == expected


def test_a_dir_star_pattern_is_the_files_directly_in_it():
    rules = codeowners.parse("docs/* @writer\n")
    assert owners(rules, "docs/a.md") == ["@writer"]
    assert owners(rules, "docs/sub/b.md") == []


def test_gitlab_sections_default_owners_and_roles():
    text = """
* @everyone

[Documentation] @docs-team
docs/
README.md @readme-owner

^[Database] @@maintainer
*.sql
/db/legacy/ @dba @dba-lead
"""
    rules = codeowners.parse(text)
    found = codeowners.owners_for(rules, "docs/intro.md")
    assert [(item["owner"], item["kind"], item["section"]) for item in found] == [
        ("@everyone", "account", ""), ("@docs-team", "account", "documentation")]
    assert owners(rules, "db/legacy/old.sql") == ["@everyone", "@dba", "@dba-lead"]
    assert owners(rules, "migrations/001.sql") == ["@everyone", "@@maintainer"]
    assert codeowners.owner_kind("@@maintainer") == "role"
    assert codeowners.owner_kind("@group/sub") == "team"
    assert codeowners.owner_kind("a@example.com") == "email"


def test_what_is_not_an_owner_or_a_rule_is_skipped():
    rules = codeowners.parse("# only a comment\n\n/ @root\n*.env not-an-owner @ok\n")
    assert [(rule.pattern, rule.owners) for rule in rules] == [("*.env", ("@ok",))]
    assert codeowners.owners_for(rules, "config/prod.env")[0]["line"] == 4
    assert codeowners.LOCATIONS["github"][0] == ".github/CODEOWNERS"
