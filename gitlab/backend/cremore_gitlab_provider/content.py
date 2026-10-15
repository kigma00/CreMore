"""gitlab content API operations; shared lifecycle stays in the platform."""
from __future__ import annotations

import re
from urllib.parse import quote

from cremore.collectors.base import CollectorError
from cremore.collectors.content import ContentCollector, ContentHTTP, build_roots


class SourceHTTP(ContentHTTP):
    def __init__(self, payload, client, **kwargs):
        super().__init__(payload, client, **kwargs)
        self.base = payload["base_url"] + "/api/v4"

    def gitlab_pages(self, route, params=None):
        page = 1
        while True:
            rows, headers = self.get(route, params={**(params or {}), "page": page, "per_page": 100})
            if not isinstance(rows, list):
                raise CollectorError("SOURCE_LIST_MALFORMED")
            yield from rows
            next_page = headers.get("x-next-page", "")
            if not next_page and len(rows) < 100:
                return
            if next_page and (not str(next_page).isdigit() or int(next_page) <= page):
                raise CollectorError("SOURCE_PAGINATION_LOOP")
            page = int(next_page) if next_page else page + 1


def roots(payload, client, budget=None):
    """Discovery does not approve content reads."""
    http = SourceHTTP(payload, client, budget=budget)
    if payload.get("project"):
        row, _ = http.get("/projects/" + quote(payload["project"], safe=""))
        yield "GITLAB_REPOSITORY", str(row["id"]), row.get("path_with_namespace", str(row["id"]))
    else:
        for row in http.gitlab_pages("/groups/" + quote(payload["group"], safe="") + "/projects", {"include_subgroups": "true"}):
            yield "GITLAB_REPOSITORY", str(row["id"]), row.get("path_with_namespace", str(row["id"]))


class Collector(ContentCollector):
    PROVIDER = "gitlab"
    ROOT_FIELD = "project"
    HTTP = SourceHTTP

    def resource_metadata(self):
        return {"source_instance": self.p["base_url"]}

    def objects(self):
        project = self.p["project"]
        route = "/projects/" + quote(project, safe="")
        project_meta, _ = self.http.get(route)
        project_path = project_meta.get("path_with_namespace", "")
        if not re.fullmatch(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+", project_path):
            raise CollectorError("GITLAB_PROJECT_MALFORMED")
        commit, _ = self.http.get(route + "/repository/commits/" + quote(self.p.get("ref") or "HEAD", safe=""))
        revision = commit.get("id", "")
        if not re.fullmatch(r"[0-9a-f]{40,64}", revision):
            raise CollectorError("GITLAB_COMMIT_MALFORMED")
        for row in self.http.gitlab_pages(route + "/repository/tree", {"ref": revision, "recursive": "true"}):
            if row.get("type") != "blob":
                continue
            key, blob = row["path"], row["id"]
            if not self.selected(key):
                continue
            if not re.fullmatch(r"[0-9a-f]{40,64}", blob):
                raise CollectorError("GITLAB_BLOB_MALFORMED")
            yield self.object(project, key, revision, lambda blob=blob: self.http.get(route + "/repository/blobs/" + blob + "/raw", raw=True),
                              revision=blob, gitlab_project_path=project_path)

    gitlab = objects


def build(payload, client, **kwargs):
    return build_roots(Collector, roots, payload, client, **kwargs)
