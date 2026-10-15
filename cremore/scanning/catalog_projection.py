"""Bounded projection from provider root tuples to platform resources."""
from cremore.collectors.base import CollectorError
from cremore.scanning.scope import resource

MAX_LISTED = 1_000_000

def enterprise_resources(roots, payload, kind, cid, client, now, request_budget):
    """Existing enterprise discovery projection; provider modules own dispatch."""
    out = []
    try:
        for resource_type, identifier, label in roots(payload, client, request_budget):
            if len(out) >= min(MAX_LISTED, payload.get("max_objects", 50000)):
                return out, "PARTIAL"
            if payload.get("reference") and identifier != payload["reference"]:
                continue
            out.append(resource(kind, cid, resource_type, identifier, str(label)[:1024], identifier,
                                payload.get("base_url", "gcp"), now=now))
    except CollectorError:
        if not out:
            raise
        return out, "PARTIAL"
    return out, "PARTIAL" if payload.get("reference") else "COMPLETE"
