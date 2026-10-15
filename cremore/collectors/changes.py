"""What changed under a root, as a change feed (``changes_since``) or a queued notification
(``queue_changes``) reports it; pure, so provider libraries can import it.

A source module may define ``queue_changes(body, attributes, roots)`` to read its own
notifications from a customer's queue (cremore.scanning.triggers): it returns
``{resource_id: Changes}`` for the roots the notification moved, ``{}`` when it
recognises the notification but nothing under ``roots`` is to be read (another branch,
a folder created), or None when the notification is not its own. A notification about
a resource outside ``roots`` raises ``CollectorError("EVENT_OUT_OF_SCOPE")``.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Changes:
    head: str
    # Changed paths when the provider names them exactly; None: unknown, read the whole root.
    paths: list[str] | None = field(default_factory=list)
    # History was rewritten or the old cursor is gone: read the root from scratch.
    rewritten: bool = False
    # Why the whole root is read (a stable code for the record).
    reason: str | None = None
    # A path was removed or renamed; only collectors that confirm a missing exact path take it.
    removals: bool = False


def pushed(root, ref, default_branch=None) -> bool:
    """Whether a push to ``ref`` moved the branch ``root`` reads.

    A root without a ref reads the default branch; when the notification does not
    name the default branch, any branch push counts (the read finds nothing new).
    """
    if not isinstance(ref, str) or (ref.startswith("refs/") and not ref.startswith("refs/heads/")):
        return False  # a tag or another namespace moves no branch
    wanted = (root.get("ref") or "").removeprefix("refs/heads/")
    if wanted in ("", "HEAD"):
        wanted = (default_branch or "").removeprefix("refs/heads/")
        if not wanted:
            return True
    return ref.removeprefix("refs/heads/") == wanted


def reread(root, head, *, rewritten=False, reason):
    """A code push: the whole root is read again (its cached blobs are reused) or from scratch
    after a force push. File lists in push notifications are capped, so they are not trusted."""
    return {root["resource_id"]: Changes(head=head if isinstance(head, str) else "", paths=None,
                                         rewritten=bool(rewritten), reason=reason)}
