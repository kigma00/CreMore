"""Azure DevOps Services and Server Git content API operations; shared lifecycle stays in the platform."""
from __future__ import annotations

import base64
import hashlib
import re
from urllib.parse import quote

from cremore.collectors.base import CollectorError
from cremore.collectors.content import ContentCollector, ContentHTTP, build_roots

# The pure helper, not the cremore.source_config compatibility module: that one
# imports the content registry and with it every provider's source module.
from cremore.sources.validation import path

CLOUD = "https://dev.azure.com"
# Azure DevOps Server keeps older API versions; 5.0 covers Server 2019 and later.
API_VERSION = {"cloud": "7.1", "server": "5.0"}
ORGANIZATION = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,48}[A-Za-z0-9])?")
_NAME = re.compile(r"[^\x00-\x1f/\\:*?\"<>|;#$%&+=,{}\[\]]{1,64}")
_SHA = re.compile(r"[a-f0-9]{40}")


def valid_name(value):
    """A project or repository name that stays one URL segment."""
    return isinstance(value, str) and bool(_NAME.fullmatch(value)) and value.strip() == value and value not in (".", "..")


def branch_ref(value, default=None):
    """A chosen branch or HEAD names exactly one refs/heads entry."""
    if value in (None, "", "HEAD"):
        value = default
        if not value:
            raise CollectorError("AZURE_DEVOPS_DEFAULT_REF_UNAVAILABLE")
    if not isinstance(value, str) or (value.startswith("refs/") and not value.startswith("refs/heads/")):
        raise CollectorError("AZURE_DEVOPS_COMMIT_MALFORMED")
    result = value if value.startswith("refs/heads/") else "refs/heads/" + value
    if result == "refs/heads/":
        raise CollectorError("AZURE_DEVOPS_COMMIT_MALFORMED")
    return result


class SourceHTTP(ContentHTTP):
    def __init__(self, payload, client, **kwargs):
        super().__init__(payload, client, **kwargs)
        base = payload.get("base_url", CLOUD)
        self.base = base + "/" + quote(payload["organization"], safe="")
        self.api = {"api-version": API_VERSION["cloud" if base == CLOUD else "server"]}
        # A token source made for the Microsoft connection's app says so; a string is a personal access token.
        self.bearer = bool(getattr(self.token, "bearer", False))
        if self.bearer and base != CLOUD:
            # The app's Microsoft Entra token is for Azure DevOps Services only; a server address never gets it.
            raise CollectorError("AZURE_DEVOPS_ENTRA_TOKEN_CLOUD_ONLY")
        if not self.token and base == CLOUD:
            # No stored credential: the worker's own Microsoft Entra identity (the Microsoft connection's
            # workload identity), as the Blob source reads with it.
            from cremore_azure_provider.app_certificate import SCOPES
            from cremore_azure_provider.metadata.transport import default_token
            self.token, self.bearer = default_token(SCOPES["devops"]), True

    def authorization(self, token):
        if self.bearer:
            return "Bearer " + token
        # A personal access token is sent as the Basic password with an empty user name.
        return "Basic " + base64.b64encode((":" + token).encode()).decode()

    def repositories(self, project):
        return "/" + quote(project, safe="") + "/_apis/git/repositories"

    def tfvc(self, project):
        return "/" + quote(project, safe="") + "/_apis/tfvc"


# A Git repository name cannot contain "$"; the TFVC root of a project uses it.
TFVC_ROOT = "$"


def roots(payload, client, budget=None):
    """Discovery does not approve content reads."""
    http = SourceHTTP(payload, client, budget=budget)
    if payload.get("version_control") == "tfvc":
        # The project's TFVC root must exist; there are no repositories or branches here.
        http.get(http.tfvc(payload["project"]) + "/items", params={
            **http.api, "path": "$/" + payload["project"], "recursionLevel": "None"})
        identifier = "/".join((payload["organization"], payload["project"], TFVC_ROOT))
        yield "AZURE_DEVOPS_TFVC", identifier, identifier
        return
    route = http.repositories(payload["project"])
    if payload.get("repository"):
        row, _ = http.get(route + "/" + quote(payload["repository"], safe=""), params=http.api)
        rows = [row]
    else:
        body, _ = http.get(route, params=http.api)
        rows = body.get("value") if isinstance(body, dict) else None
        if not isinstance(rows, list):
            raise CollectorError("SOURCE_LIST_MALFORMED")
    for row in rows:
        name = row.get("name") if isinstance(row, dict) else None
        if not valid_name(name):
            raise CollectorError("AZURE_DEVOPS_REPOSITORY_MALFORMED")
        if row.get("isDisabled") is True:
            continue  # A disabled repository cannot be read; it is not listed as scannable.
        identifier = "/".join((payload["organization"], payload["project"], name))
        yield "AZURE_DEVOPS_REPOSITORY", identifier, identifier


class Collector(ContentCollector):
    PROVIDER = "azure_devops"
    ROOT_FIELD = "repository"
    HTTP = SourceHTTP

    @classmethod
    def root_payload(cls, payload, identifier):
        return {**payload, cls.ROOT_FIELD: identifier.rsplit("/", 1)[1]}

    def resource_metadata(self):
        # Collections of two servers can share names; the instance keeps their locations apart.
        return {"source_instance": self.p.get("base_url", CLOUD)}

    def path_comparison(self, value):
        return value.lower() if self.p.get("repository") == TFVC_ROOT else value

    def items(self, route, params, scope, folder, fold=str):
        """Bound all listed entries and release each parsed listing before descending."""
        pending, count = [scope], 0
        while pending:
            scope = pending.pop()
            try:
                body, _ = self.http.get(route + "/items", params={**params, "scopePath": scope, "recursionLevel": "Full"})
                split = False
            except CollectorError as exc:
                if exc.code != "SOURCE_RESPONSE_TOO_LARGE":
                    raise
                body, _ = self.http.get(route + "/items", params={**params, "scopePath": scope, "recursionLevel": "OneLevel"})
                split = True
            rows = body.get("value") if isinstance(body, dict) else None
            if not isinstance(rows, list):
                raise CollectorError("SOURCE_LIST_MALFORMED")
            children, row = [], None
            for row in rows:
                child = str(row.get("path", "")) if isinstance(row, dict) else ""
                path(child)  # Also bound retained folder paths, before any descendant request.
                if folder(row) and fold(child) == fold(scope):
                    continue
                if count >= self.max_objects:
                    raise CollectorError("SOURCE_OBJECT_LIMIT")
                count += 1
                if split and folder(row):
                    if not fold(child).startswith(fold(scope).rstrip("/") + "/"):
                        raise CollectorError("AZURE_DEVOPS_TREE_MALFORMED")
                    children.append(child)
                else:
                    yield row
            pending.extend(reversed(children))
            del body, rows, row

    def tfvc_objects(self):
        organization, project = self.p["organization"], self.p["project"]
        resource, route, api = f"{organization}/{project}/{TFVC_ROOT}", self.http.tfvc(project), self.http.api
        top = "$/" + project
        changesets, _ = self.http.get(route + "/changesets", params={**api, "$top": 1, "searchCriteria.itemPath": top})
        rows = changesets.get("value") if isinstance(changesets, dict) else None
        changeset = rows[0].get("changesetId") if rows and isinstance(rows[0], dict) else None
        if type(changeset) is not int or changeset <= 0:
            raise CollectorError("AZURE_DEVOPS_CHANGESET_UNAVAILABLE")
        # Every listing and read names the same changeset, as a Git read names one commit.
        version = {"versionDescriptor.version": str(changeset), "versionDescriptor.versionType": "changeset"}
        seen = set()
        folder = lambda row: isinstance(row, dict) and row.get("isFolder") is True
        for item in self.items(route, {**api, **version}, top, folder, str.lower):
            if (not isinstance(item, dict) or item.get("isFolder") or item.get("isSymLink")
                    or (item.get("deletionId") or 0) > 0):
                continue
            full = str(item.get("path", ""))
            # TFVC paths compare case-insensitively.
            if not full.lower().startswith(top.lower() + "/"):
                raise CollectorError("AZURE_DEVOPS_TREE_MALFORMED")
            key = path(full[len(top) + 1:])
            if not key or key in seen:
                raise CollectorError("AZURE_DEVOPS_TREE_MALFORMED")
            if len(seen) >= self.max_objects:
                raise CollectorError("SOURCE_OBJECT_LIMIT")
            seen.add(key)
            if not self.selected(key):
                continue
            size = item.get("size") or 0
            if type(size) is not int or size > self.http.max_bytes:
                self.listed(key)
                self.failed_objects += 1
                continue
            # The changeset the item last changed in names its content, so an unchanged item is not read
            # again. This source's cache is keyed by revision alone (a Git blob id), so two items of one
            # changeset must differ: by the exact path, never by the listing's MD5 (``hashValue``), which
            # anyone who can check in could make collide with a clean file and so skip the read.
            last = item.get("version")
            revision = (f"{last}:path:{hashlib.sha256(key.encode()).hexdigest()}"
                        if type(last) is int and 0 < last <= changeset else None)
            yield self.object(resource, key, str(changeset), lambda full=full: self.http.get(
                route + "/items", params={**api, "path": full, **version}, raw=True,
                headers={"Accept": "application/octet-stream"}), revision=revision)

    def objects(self):
        if self.p["repository"] == TFVC_ROOT:
            yield from self.tfvc_objects()
            return
        organization, project, repository = self.p["organization"], self.p["project"], self.p["repository"]
        resource = f"{organization}/{project}/{repository}"
        route = self.http.repositories(project) + "/" + quote(repository, safe="")
        api = self.http.api
        metadata, _ = self.http.get(route, params=api)
        if metadata.get("isDisabled") is True:
            raise CollectorError("AZURE_DEVOPS_REPOSITORY_DISABLED")
        selected_ref = branch_ref(self.p.get("ref"), metadata.get("defaultBranch"))
        # The refs filter is a prefix match; only the exact branch name pins the commit.
        refs, _ = self.http.get(route + "/refs", params={**api, "filter": selected_ref.removeprefix("refs/")})
        commit = next((row.get("objectId") for row in (refs.get("value") or [])
                       if isinstance(row, dict) and row.get("name") == selected_ref), None)
        if not isinstance(commit, str) or not _SHA.fullmatch(commit):
            raise CollectorError("AZURE_DEVOPS_COMMIT_MALFORMED")
        version = {"versionDescriptor.version": commit, "versionDescriptor.versionType": "commit"}
        seen = set()
        folder = lambda row: isinstance(row, dict) and row.get("gitObjectType") == "tree"
        for item in self.items(route, {**api, **version}, "/", folder):
            if not isinstance(item, dict) or item.get("gitObjectType") != "blob":
                continue
            key, blob = path(str(item.get("path", ""))), item.get("objectId")
            if not key or key in seen or not isinstance(blob, str) or not _SHA.fullmatch(blob):
                raise CollectorError("AZURE_DEVOPS_TREE_MALFORMED")
            if len(seen) >= self.max_objects:
                raise CollectorError("SOURCE_OBJECT_LIMIT")
            seen.add(key)
            if self.selected(key):
                # Blob IDs are content addresses: the read is the listed commit's exact file.
                yield self.object(resource, key, commit, lambda blob=blob: self.http.get(
                    route + "/blobs/" + blob, params={**api, "$format": "octetstream"}, raw=True), revision=blob)

    azure_devops = objects


def build(payload, client, **kwargs):
    return build_roots(Collector, roots, payload, client, **kwargs)
