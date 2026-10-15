# Adapted from publish/develop_atlassian 49abdc11a998f61917e151ab276e84c7a21815ea (atlassian_collector/collector.py).
"""Collect supported sources independently and retain partial observations."""

from collections import Counter
from dataclasses import asdict

from .metadata import group_inventory, normalize, oauth_link_candidates, utc_now
from .specs import DEFAULT_SOURCES, SOURCES
from .steps import CollectionInterrupted, check_collection, completed_report, consume, step


def collect_source(client, source, now=utc_now):
    return consume(iter_source(client, source, now))


def iter_source(client, source, now=utc_now):
    cached = completed_report(client, source)
    if cached is not None:
        return cached
    report, observations = yield from _iter_source(client, source, now)
    yield step(source, report, completed=True)
    return report, observations


def _iter_source(client, source, now=utc_now):
    spec, limits = SOURCES[source], client.limits
    result = {
        "coverage": "failed",
        "reason": None,
        "requests": 0,
        "pages": 0,
        "received_records": 0,
        "accepted_records": 0,
        "invalid_records": 0,
        "duplicate_observations": 0,
        "last_http_status": None,
        "query": {"pageSize": 20} if spec["paged"] else {},
        "coverage_basis": "cursor" if spec["paged"] else "documented_array",
        "redactions": {
            "secret_fields_omitted": 0,
            "sensitive_values_omitted": 0,
            "truncated_nodes": 0,
        },
    }
    observations, seen_ids, seen_cursors = [], set(), set()
    cursor = None

    def stop(reason):
        result["coverage"] = "partial" if result["pages"] else "failed"
        result["reason"] = reason
        return result, observations

    while result["pages"] < limits.max_pages:
        check_collection(client)
        query = dict(result["query"])
        if cursor:
            query["cursor"] = cursor
        attempts_before = getattr(client, "requests", None)
        try:
            page = client.fetch(source, query)
        except CollectionInterrupted:
            raise
        except Exception:  # noqa: BLE001 - provider errors must not expose authentication.
            # Never embed exception text, URLs, cursor values or authentication.
            attempts_after = getattr(client, "requests", None)
            if (
                type(attempts_before) is int
                and type(attempts_after) is int
                and attempts_after >= attempts_before
            ):
                result["requests"] += attempts_after - attempts_before
            return stop("fetch_exception")
        result["requests"] += page.attempts
        result["last_http_status"] = page.status
        if page.reason:
            return stop(page.reason)
        if page.status != 200:
            return stop("unexpected_http_status")
        array_variant = spec.get("allow_array_variant", False) and isinstance(page.body, list)
        records = (
            page.body.get("data")
            if spec["paged"] and isinstance(page.body, dict)
            else (page.body if not spec["paged"] else None)
        )
        if array_variant:
            records = page.body
            result["coverage_basis"] = "support_confirmed_array"
        if not isinstance(records, list):
            return stop("unexpected_collection_shape")
        result["pages"] += 1
        result["received_records"] += len(records)
        observed_at = now()
        page_observations = []
        for record in records:
            check_collection(client)
            if len(observations) >= limits.max_records:
                yield step(source, result, observations=page_observations)
                return stop("record_limit")
            record, omissions = client.snapshot(record)
            result["redactions"] = dict(Counter(result["redactions"]) + Counter(omissions))
            observation = normalize(
                source, record, observed_at, allow_service_oauth_variant=array_variant
            )
            if observation is None:
                result["invalid_records"] += 1
                continue
            identifier = observation["fields"][spec["id_field"]]["value"]
            if identifier in seen_ids:
                result["duplicate_observations"] += 1
            seen_ids.add(identifier)
            org_field = spec["org_field"]
            if observation["record_contract"] == "service_account_oauth_client":
                org_field = "serviceAccount.orgId"
            field = observation["fields"].get(org_field, {})
            if field.get("state") == "present" and field["value"] != client.org_id:
                observation["warnings"].append("queried_org_mismatch:" + org_field)
            observations.append(observation)
            page_observations.append(observation)
            result["accepted_records"] += 1
        yield step(source, result, observations=page_observations)
        if result["redactions"].get("truncated_nodes", 0):
            return stop("snapshot_limit")
        if array_variant:
            if result["invalid_records"]:
                return stop("invalid_records")
            result["coverage"], result["reason"] = "unverified", "pagination_contract_unverified"
            return result, observations
        next_cursor = None
        if spec["paged"]:
            links = page.body.get("links")
            if not isinstance(links, dict):
                return stop("missing_pagination_contract")
            # API Access includes a next cursor only when more results follow; the last page has none.
            next_cursor = links.get("next")
            if next_cursor is not None and (
                not isinstance(next_cursor, str) or len(next_cursor) > 8192
            ):
                return stop("invalid_cursor")
        if not next_cursor:
            if result["invalid_records"]:
                return stop("invalid_records")
            result["coverage"] = "unverified" if result["duplicate_observations"] else "complete"
            result["reason"] = "duplicate_ids" if result["duplicate_observations"] else None
            return result, observations
        if next_cursor in seen_cursors:
            return stop("repeated_cursor")
        if len(observations) >= limits.max_records:
            return stop("record_limit")
        seen_cursors.add(next_cursor)
        cursor = next_cursor
    return stop("page_limit")


def collect(client, sources=None, *, now=utc_now):
    return consume(iter_collect(client, sources, now=now))


def iter_collect(client, sources=None, *, now=utc_now):
    selected = list(DEFAULT_SOURCES) if sources is None else list(sources)
    if (
        not selected
        or len(selected) != len(set(selected))
        or any(s not in SOURCES for s in selected)
    ):
        raise ValueError("Choose distinct supported sources")
    result = {
        "schema_version": 3,
        "provider": "atlassian",
        "environment": "cloud",
        "queried_org_id": client.org_id,
        "started_at": now(),
        "inventory_complete": False,
        "requested_sources": selected,
        "limits": asdict(client.limits),
        "collections": {s: {"coverage": "not_requested"} for s in SOURCES},
    }
    observations = []
    for source in selected:
        report, items = yield from iter_source(client, source, now)
        result["collections"][source] = report
        observations.extend(items)
    inventory = group_inventory(observations)
    candidates = oauth_link_candidates(inventory)
    candidate_keys = {(kind, c["provider_id"]) for c in candidates for kind in c["kinds"]}
    conflicts = sum(bool(entry["conflict_fields"]) for entry in inventory)
    coverages = [result["collections"][s]["coverage"] for s in selected]
    if all(c == "complete" for c in coverages) and not conflicts and not candidates:
        run_status = "complete"
    elif not any(result["collections"][s]["pages"] for s in selected):
        run_status = "failed"
    elif any(c in ("failed", "partial") for c in coverages) or conflicts:
        run_status = "partial"
    else:
        run_status = "unverified"
    result.update(
        {
            "finished_at": now(),
            "run_status": run_status,
            "inventory": inventory,
            "identity_link_candidates": candidates,
            "counts": {
                "observations": len(observations),
                "identities": len(inventory),
                "unambiguous_credentials": sum(
                    not e["conflict_fields"] and (e["kind"], e["provider_id"]) not in candidate_keys
                    for e in inventory
                ),
                "conflicted_identities": conflicts,
            },
            "warning_counts": dict(
                sorted(Counter(w for o in observations for w in o["warnings"]).items())
            ),
        }
    )
    return result


def safe_summary(result):
    """No IDs, names, emails, scopes, cursor values, or response text on stdout."""
    return {
        "schema_version": result["schema_version"],
        "run_status": result["run_status"],
        "inventory_complete": False,
        "counts": result["counts"],
        "warning_counts": result["warning_counts"],
        "candidate_link_count": len(result["identity_link_candidates"]),
        "collections": {
            source: {k: v for k, v in report.items() if k not in ("query",)}
            for source, report in result["collections"].items()
        },
    }
