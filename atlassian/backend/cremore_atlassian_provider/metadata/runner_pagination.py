# Adapted from publish/develop_atlassian 49abdc11a998f61917e151ab276e84c7a21815ea (atlassian_collector/runner_pagination.py).
"""Runner next links may use UUID paths; identities come from public reads."""

import re
from urllib.parse import quote, urljoin

from .read_operations import PaginationScopeError, validate_next_url


def bitbucket_uuid(value):
    if isinstance(value, str) and re.fullmatch(
        r"\{[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\}", value
    ):
        return value.lower()
    return None


class RunnerIdentities:
    """Do not learn identities from next links, Runner records or their links."""

    def __init__(self, workspace):
        self.workspace = workspace
        self.workspace_ids = set()
        self.repository_ids = {}

    def observe(self, operation, body):
        if operation == "workspace":
            candidates = [body]
        elif operation == "repositories" and isinstance(body, dict):
            candidates = body.get("values", [])
        else:
            return
        if not isinstance(candidates, list):
            return
        for item in candidates:
            if not isinstance(item, dict):
                continue
            workspace = item if operation == "workspace" else item.get("workspace")
            if not isinstance(workspace, dict) or workspace.get("slug") != self.workspace:
                continue
            workspace_id = bitbucket_uuid(workspace.get("uuid"))
            if workspace_id is None:
                continue
            self.workspace_ids.add(workspace_id)
            if operation == "repositories":
                slug, repo_id = item.get("slug"), bitbucket_uuid(item.get("uuid"))
                if (
                    isinstance(slug, str)
                    and re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}", slug)
                    and repo_id is not None
                ):
                    self.repository_ids.setdefault(slug, set()).add((workspace_id, repo_id))

    def internal_paths(self, operation, target):
        if len(self.workspace_ids) != 1:
            return ()
        workspace_id = next(iter(self.workspace_ids))
        if operation == "workspace-runners":
            path = "/internal/workspaces/" + workspace_id + "/pipelines-config/runners"
        elif operation == "repository-runners":
            identities = self.repository_ids.get(target, set())
            if len(identities) != 1:
                return ()
            repo_workspace_id, repo_id = next(iter(identities))
            if repo_workspace_id != workspace_id:
                return ()
            path = (
                "/internal/repositories/"
                + workspace_id
                + "/"
                + repo_id
                + "/pipelines-config/runners"
            )
        else:
            return ()
        # Literal braces and their percent-encoded spelling identify the same
        # UUID path. No other path decoding or normalization is permitted.
        encoded = quote(path, safe="/")
        return (path, encoded, encoded.replace("%7B", "%7b").replace("%7D", "%7d"))

    def next_url(self, public_url, current_url, operation, target, next_url):
        # Validate the original spelling before resolving relative links, so
        # whitespace, credentials, fragments and cross-origin links stay denied.
        try:
            validate_next_url(current_url, next_url)
        except PaginationScopeError:
            pass
        resolved = urljoin(current_url, next_url)
        try:
            return validate_next_url(public_url, resolved)
        except PaginationScopeError:
            pass
        for path in self.internal_paths(operation, target):
            try:
                return validate_next_url("https://api.bitbucket.org" + path, resolved)
            except PaginationScopeError:
                continue
        raise PaginationScopeError("Pagination target outside this metadata resource")
