"""Which approved Confluence pages changed since the last look (change feed, design 4.3).

One CQL search per space and poll finds the pages modified in the window, with their
version numbers: ``type = page and space = "KEY" and lastmodified >= now("-Nm")``. The
relative ``now()`` form keeps the window on the server's clock, whatever time zone the
calling account uses; the window starts a few minutes before the oldest last look, and
only a version different from the one last seen counts, so the overlap reads nothing
twice. A changed page is read again: its body, and its attachments, of which the
detection cache skips every version it already scanned.
[CQL](https://developer.atlassian.com/cloud/confluence/advanced-searching-using-cql/)
"""

from __future__ import annotations

import datetime as _dt
import math
from urllib.parse import quote

from cremore.collectors.base import NO_WAIT, CollectorError
from cremore.collectors.changes import Changes

from .confluence_content import SourceHTTP

OVERLAP = _dt.timedelta(minutes=5)
MAX_WINDOW_MINUTES = 60 * 24 * 7


def changes_since_batch(payload, roots, states, *, http_client, request_budget):
    """``{resource_id: Changes}`` for approved page roots of one space.

    ``states`` maps each root to its last cursor and when it was checked; a root never
    checked only records that it was seen (the scan that set its state covers the present).
    """
    out, known = {}, []
    for root in roots:
        state = states.get(root["resource_id"]) or {}
        if state.get("cursor") and state.get("checked_at"):
            known.append((root, state))
        else:
            out[root["resource_id"]] = Changes(head="seen")
    if not known:
        return out
    now = _dt.datetime.now(_dt.UTC)
    since = min(state["checked_at"] for _root, state in known)
    minutes = math.ceil((now - since + OVERLAP).total_seconds() / 60)
    if minutes > MAX_WINDOW_MINUTES:
        # Unchecked for over a week: the window is not trusted and every page is read again.
        out.update({root["resource_id"]: Changes(head="window:" + now.isoformat(), paths=None,
                                                 reason="CONFLUENCE_WINDOW_TOO_OLD") for root, _state in known})
        return out
    http = SourceHTTP(payload, http_client(), budget=request_budget)
    http.pacer = NO_WAIT  # polled on the worker's control loop: a rate limit or a busy server ends the look at once
    http.base = http.site()
    space = payload["space"]
    if payload["edition"] == "cloud":
        # CQL's space field takes the space key; a Cloud source names its space by ID (read:space:confluence).
        found, _ = http.get("/api/v2/spaces/" + quote(space, safe=""))
        space = found.get("key") if isinstance(found, dict) else None
        if not isinstance(space, str) or not space:
            raise CollectorError("CONFLUENCE_SPACE_MALFORMED")
    # CQL search is the v1 REST API on Cloud as well; a key is quoted, as a numeric-looking one must be.
    space = space.replace("\\", "\\\\").replace('"', '\\"')
    cql = f'type = page and space = "{space}" and lastmodified >= now("-{max(1, minutes)}m")'
    versions = {}
    for row in http.confluence_pages("/rest/api/content/search", {"cql": cql, "expand": "version"}):
        if not isinstance(row, dict) or not isinstance(row.get("version"), dict):
            raise CollectorError("CONFLUENCE_SEARCH_MALFORMED")
        versions[str(row.get("id"))] = "v" + str(row["version"].get("number"))
    for root, state in known:
        found = versions.get(str(root["provider_resource_id"]))
        if found is None or found == state["cursor"]:
            out[root["resource_id"]] = Changes(head=state["cursor"])
        else:
            out[root["resource_id"]] = Changes(head=found, paths=None, reason="CONFLUENCE_PAGE_MODIFIED")
    return out
