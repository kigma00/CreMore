"""Shared construction for bounded provider content libraries."""


def object_limit(value):
    if value is None:
        from cremore.collectors.base import DEFAULT_MAX_OBJECT_BYTES

        return DEFAULT_MAX_OBJECT_BYTES
    return value


def enterprise_collector(content, payload, *, http_client_factory=None, max_object_bytes=None):
    if http_client_factory is None:
        raise ValueError("source job requires an HTTP client")
    return content.build(payload, http_client_factory(), max_object_bytes=object_limit(max_object_bytes))


def enterprise_root(content, payload, root, *, http_client_factory=None,
                    max_object_bytes=None, request_budget=None):
    if http_client_factory is None:
        raise ValueError("source scope requires an HTTP client")
    scope = {**payload, **root}
    # A plan may narrow a connection's declared paths, never widen them.
    scope["_connection_scope"] = {key: payload[key] for key in
        ("prefixes", "paths", "excluded_prefixes", "excluded_paths") if key in payload}
    return content.build(scope, http_client_factory(), request_budget=request_budget,
                 max_object_bytes=object_limit(max_object_bytes))


def enterprise_resources(content, payload, kind, cid, *, s3_client=None, http_client=None, now, request_budget):
    from cremore.collectors.base import CollectorError
    from cremore.scanning.catalog_projection import enterprise_resources

    if http_client is None:
        raise CollectorError("NEEDS_CONFIGURATION")
    return enterprise_resources(content.roots, payload, kind, cid, http_client(), now, request_budget)
