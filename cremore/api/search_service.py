"""Role-scoped inventory search shared by dashboard and other API consumers."""

from __future__ import annotations

from cremore.api.auth import role_at_least

SEARCH_ROLES = {"connection": "viewer", "aws_account": "viewer",
                "finding": "viewer", "asset": "analyst", "managed_object": "viewer"}


def managed_object_search(repo, needle: str, limit: int, people: bool = False):
    """The schema 2 issuer/vault inventory as search hits.

    Only objects an observation actually recorded are searchable, so a hit is
    always something a collection saw. The store does the filtering and counting.
    A people-directory collection's people are hits only for an Analyst or above
    (``people``), as the people directory is (cremore.api.metadata_coverage.PEOPLE).
    """
    from cremore.api.metadata_coverage import PEOPLE
    from cremore.coverage.metadata_store import MetadataStore

    page = MetadataStore(repo).inventory(q=needle, limit=limit, exclude_purposes=() if people else PEOPLE)
    items = [{"kind": "managed_object", "id": str(row["id"]), "label": row["object_id"],
              "provider": row["provider"],
              # Tenancy is only shown when the provider confirmed it; otherwise
              # the origin is the honest answer for "where is this object".
              "context": row["tenant"] if row["tenant_confirmed"] else row["origin"],
              "detail": row["object_kind"]}
             for row in page["items"]]
    return items, page["total"]


def search_payload(repo, role: str, q: str, limit: int) -> dict:
    """Search the objects this role may already list, with their context.

    Filtering, ordering, limiting and counting happen in the repository so the
    answer does not depend on reading every row into memory first.
    """

    needle = q.strip().lower()[:200]

    def group(kind: str, search):
        if not role_at_least(role, SEARCH_ROLES[kind]):
            return {"kind": kind, "requires_role": SEARCH_ROLES[kind], "permitted": False,
                    "searched": False, "reason": "ROLE_REQUIRED", "total": 0, "items": []}
        items, total, *rest = search()
        found = {"kind": kind, "requires_role": SEARCH_ROLES[kind], "permitted": True,
                 "searched": True, "reason": "", "total": total, "items": items}
        if rest and rest[0]:
            # A partial catalog means absence here is not proof of absence.
            found["partial"] = True
        return found

    return {
        "query": needle,
        "limit": limit,
        "role": role,
        "groups": [
            group("connection", lambda: repo.search_connections(needle, limit)),
            group("aws_account", lambda: repo.search_aws_accounts(needle, limit)),
            group("finding", lambda: repo.search_findings(needle, limit)),
            group("asset", lambda: repo.search_assets(needle, limit)),
            group("managed_object", lambda: managed_object_search(repo, needle, limit, role_at_least(role, "analyst"))),
        ],
    }
