"""Small in-memory API inputs for collector regression tests only."""

from copy import deepcopy
from urllib.parse import parse_qs, urlsplit

from ..http import Client, CollectionError, Response


class FakeClient(Client):
    def __init__(self, config, routes=None):
        self.config = config
        self.origin = config.base_url.rstrip("/")
        self.routes = routes or {"/user": {"id": 1}, "/personal_access_tokens": []}
        self.requests = self.retries = 0
        self.calls = []
        self.failures = {}
        self.graphql_body = {"data": {"project": {"pipelineTriggers": {
            "nodes": [], "pageInfo": {"hasNextPage": False, "endCursor": None},
        }}}}

    def deferred_rate_classes(self):
        return frozenset()

    def request(self, url, query=None, variables=None):
        url = self.checked_url(url, graphql=query is not None)
        self.requests += 1
        self.calls.append(url)
        parts = urlsplit(url)
        params = parse_qs(parts.query)
        path = parts.path.removeprefix("/api/v4")
        page = int(params.get("page", ["1"])[0])
        if failure := self.failures.get((path, page)):
            raise CollectionError("FORBIDDEN" if failure == 403 else "HTTP_ERROR", "test", failure)
        if query:
            return Response(deepcopy(self.graphql_body), {})
        if path not in self.routes:
            raise AssertionError(f"Unexpected test API path: {path}")
        body = deepcopy(self.routes[path])
        if isinstance(body, list):
            size = int(params.get("per_page", ["100"])[0])
            return Response(body[(page - 1) * size:page * size], {
                "x-next-page": str(page + 1) if page * size < len(body) else "",
            })
        return Response(body, {})


def inventory_client(config):
    """One token per family, plus two PATs for duplicate names and pagination."""
    client = FakeClient(config)
    routes = client.routes
    for uid in (1, 2, 10, 12, 1000, 1001):
        routes[f"/users/{uid}"] = {"id": uid, "username": f"user-{uid}"}
    routes.update({
        "/groups/10": {"id": 10, "parent_id": None},
        "/groups/20": {"id": 20, "parent_id": 10},
        "/groups/10/subgroups": [{"id": 20, "parent_id": 10}],
        "/groups/10/projects": [{"id": 100}],
        "/groups/20/subgroups": [], "/groups/20/projects": [],
        "/groups/20/access_tokens": [], "/groups/20/deploy_tokens": [],
        "/groups/20/service_accounts": [],
        "/projects/100": {"id": 100, "path_with_namespace": "test/project",
                          "namespace": {"id": 10, "kind": "group"}},
    })

    def tokens(path, rows, *, detail=True):
        routes[path] = rows
        if detail:
            routes.update({f"{path}/{row['id']}": deepcopy(row) for row in rows})

    own = [{"id": identifier, "user_id": 1, "name": "same-name", "active": True,
            "revoked": False, "scopes": ["read_api"], "expires_at": "2027-01-01"}
           for identifier in (101, 102, 103)]
    tokens("/personal_access_tokens", own)
    tokens("/groups/10/access_tokens", [{"id": 201, "user_id": 10}])
    tokens("/projects/100/access_tokens", [{"id": 203, "user_id": 12}])
    routes["/groups/10/manage/personal_access_tokens"] = [own[0]]
    routes["/groups/10/manage/resource_access_tokens"] = [
        {"id": 201, "user_id": 10, "resource_type": "group", "resource_id": 10},
        {"id": 203, "user_id": 12, "resource_type": "project", "resource_id": 100},
    ]
    for root, token_id, user_id, service_pat in (
        ("/groups/10", 301, 1000, 401), ("/projects/100", 302, 1001, 402),
    ):
        tokens(root + "/deploy_tokens", [{"id": token_id, "revoked": False}])
        routes[root + "/service_accounts"] = [{"id": user_id}]
        tokens(root + f"/service_accounts/{user_id}/personal_access_tokens",
               [{"id": service_pat, "user_id": user_id}], detail=False)
    tokens("/projects/100/triggers", [{
        "id": 501, "last_used": None, "owner": {"id": 1},
        "token": "SYNTHETIC_DO_NOT_PERSIST_TRIGGER",
    }])
    tokens("/projects/100/cluster_agents", [{"id": 50}])
    tokens("/projects/100/cluster_agents/50/tokens", [{
        "id": 601, "agent_id": 50, "created_by_user_id": 2,
    }])
    routes["/projects/100/error_tracking/client_keys"] = [{
        "id": 701, "active": True, "public_key": "SYNTHETIC_DO_NOT_PERSIST_CLIENT_KEY",
    }]
    client.graphql_body["data"]["project"]["pipelineTriggers"]["nodes"] = [{
        "id": "gid://gitlab/Ci::Trigger/501", "canAccessProject": True,
        "hasTokenExposed": False, "owner": {"id": "gid://gitlab/User/1"},
    }]
    return client
