# Adapted from publish/develop_atlassian 49abdc11a998f61917e151ab276e84c7a21815ea (atlassian_collector/discovery.py).
"""Collect provider metadata before selection/normalization, with bounded fan-out."""

from collections import Counter
from dataclasses import asdict

from .identities import RecordQuality
from .metadata import utc_now
from .read_operations import (
    ACCOUNT_COUNT_OPERATIONS,
    ACCOUNT_DETAIL_OPERATIONS,
    READ_OPERATIONS,
    STATIC_OPERATIONS,
    PaginationScopeError,
    valid_identifier,
)
from .snapshot import field_catalog
from .steps import CollectionInterrupted, check_collection, completed_report, consume, step


def collection_records(spec, body):
    shape = spec["shape"]
    if shape == "array" or (shape == "array_or_data" and isinstance(body, list)):
        return body if isinstance(body, list) else None, None
    if shape in ("data", "array_or_data", "items", "values", "public_key_bundle", "jwks"):
        key = (
            "keys"
            if shape == "jwks"
            else "values"
            if shape == "public_key_bundle"
            else shape
            if shape in ("items", "values")
            else "data"
        )
        return (
            body.get(key) if isinstance(body, dict) and isinstance(body.get(key), list) else None
        ), key
    return None, None


def valid_scalar_shape(shape, body):
    if shape in ("public_key_text", "public_key_bundle"):
        return (
            isinstance(body, str)
            and body.strip().startswith("-----BEGIN PGP PUBLIC KEY BLOCK-----")
            and body.strip().endswith("-----END PGP PUBLIC KEY BLOCK-----")
        )
    if shape == "integer":
        return type(body) is int and body >= 0
    if shape == "total":
        return isinstance(body, dict) and type(body.get("total")) is int and body["total"] >= 0
    if shape == "object":
        return isinstance(body, dict)
    if shape == "account_counts":
        return (
            isinstance(body, dict)
            and isinstance(body.get("validServiceAccountIds"), list)
            and isinstance(body.get("invalidServiceAccountIds"), list)
            and all(valid_identifier(v, 100) for v in body["invalidServiceAccountIds"])
            and all(
                isinstance(v, dict)
                and valid_identifier(v.get("serviceAccountId"), 100)
                and type(v.get("credentialsCount")) is int
                and v["credentialsCount"] >= 0
                for v in body["validServiceAccountIds"]
            )
        )
    return False


def collect_operation(
    client, operation, *, identifier=None, body=None, now=utc_now, specs=READ_OPERATIONS
):
    return consume(
        iter_operation(client, operation, identifier=identifier, body=body, now=now, specs=specs)
    )


def iter_operation(
    client, operation, *, identifier=None, body=None, now=utc_now, specs=READ_OPERATIONS
):
    cached = completed_report(client, operation, identifier=identifier, body=body)
    if cached is not None:
        return cached
    report = yield from _iter_operation(
        client, operation, identifier=identifier, body=body, now=now, specs=specs
    )
    yield step(operation, report, completed=True)
    return report


def _iter_operation(
    client, operation, *, identifier=None, body=None, now=utc_now, specs=READ_OPERATIONS
):
    spec = specs[operation]
    report = {
        "operation": operation,
        "method": spec.get("method", "GET"),
        "coverage": "failed",
        "reason": None,
        "requests": 0,
        "received_records": 0,
        "saved_records": 0,
        "last_http_status": None,
        "pages": [],
        "redactions": {},
    }
    if identifier is not None:
        report["target_id"] = identifier
    if body is not None:
        report["requested_account_ids"] = list(body)
    cursor, next_url, seen = None, None, set()
    expected_records = None
    quality = RecordQuality(spec.get("identity_fields"))

    def finish(coverage, reason=None):
        report["record_quality"] = dict(quality.counts)
        if coverage == "complete" and quality.reason():
            coverage, reason = "unverified", quality.reason()
        report["coverage"], report["reason"] = coverage, reason
        return report

    def stop(reason):
        return finish("partial" if report["pages"] else "failed", reason)

    for _ in range(client.limits.max_pages):
        check_collection(client)
        before = client.requests
        try:
            response = client.read_metadata(
                operation, identifier=identifier, body=body, cursor=cursor, next_url=next_url
            )
        except PaginationScopeError:
            report["requests"] += max(0, client.requests - before)
            return stop("pagination_target_outside_resource")
        except CollectionInterrupted:
            raise
        except Exception:  # noqa: BLE001 - fixed diagnostics omit provider exception text.
            report["requests"] += max(0, client.requests - before)
            return stop("metadata_request_exception")
        report["requests"] += response.attempts
        report["last_http_status"] = response.status
        if response.reason or response.status != 200:
            return stop(response.reason or "unexpected_http_status")
        records, container = collection_records(spec, response.body)
        observed_array = spec["shape"] == "array_or_data" and isinstance(response.body, list)
        shape_valid = records is not None or valid_scalar_shape(spec["shape"], response.body)
        selected_body = response.body
        received = len(records) if records is not None else 0
        report["received_records"] += received
        available = max(0, client.limits.max_records - report["saved_records"])
        kept = min(received, available)
        if records is not None and kept < received:
            selected_body = (
                dict(response.body, **{container: records[:kept]}) if container else records[:kept]
            )
        snapshot, omissions = client.snapshot(selected_body)
        saved_rows, _ = collection_records(spec, snapshot)
        if saved_rows is not None:
            quality.observe(saved_rows)
        report["pages"].append(
            {
                "observed_at": now(),
                "http_status": response.status,
                "metadata": snapshot,
                "field_types": field_catalog(snapshot),
                "redactions": omissions,
                "received_records": received,
                "saved_records": kept,
            }
        )
        report["saved_records"] += kept
        report["redactions"] = dict(Counter(report["redactions"]) + Counter(omissions))
        yield step(operation, report, page=report["pages"][-1])
        if omissions["truncated_nodes"]:
            return stop("snapshot_limit")
        if kept < received:
            return stop("record_limit")
        if not shape_valid:
            return finish("unverified", "unexpected_response_shape")
        if observed_array:
            # Support confirmed this shape; pageSize is ignored and no verified
            # continuation contract exists (ECOHELP-167001).
            return finish("unverified", "pagination_contract_unverified")
        if spec["shape"] == "public_key_bundle" and isinstance(response.body, str):
            return finish("complete")
        if not spec.get("pager"):
            return finish("complete")
        # Bitbucket's optional size describes the entire list, not this page.
        # Preserve inconsistent observations, but do not call them complete.
        check_size = spec.get("pager") == "top_url" and spec["shape"] == "values"
        if check_size and "size" in response.body:
            size = response.body["size"]
            if type(size) is not int or size < 0:
                return finish("unverified", "invalid_pagination_size")
            if expected_records is not None and size != expected_records:
                return stop("pagination_size_changed")
            expected_records = size
        if (
            check_size
            and expected_records is not None
            and report["received_records"] > expected_records
        ):
            return stop("pagination_size_mismatch")
        links = (
            (response.body if spec.get("pager") == "top_url" else response.body.get("links"))
            if isinstance(response.body, dict)
            else None
        )
        if not isinstance(links, dict):
            return stop("missing_pagination_contract")
        # API Access (cursor) includes `next` only when more results follow; the last page has none.
        nxt = links.get("next")
        if nxt is None or nxt == "":
            if (
                check_size
                and expected_records is not None
                and report["received_records"] != expected_records
            ):
                return stop("pagination_size_mismatch")
            return finish("complete")
        if not isinstance(nxt, str) or len(nxt) > 8192:
            return stop("invalid_pagination")
        if nxt in seen:
            return stop("repeated_pagination")
        if report["saved_records"] >= client.limits.max_records:
            return stop("record_limit")
        seen.add(nxt)
        if spec["pager"] == "cursor":
            cursor = nxt
        else:
            next_url = nxt
    return stop("page_limit")


def iter_records(report):
    spec = READ_OPERATIONS[report["operation"]]
    for page in report["pages"]:
        records, _ = collection_records(spec, page["metadata"])
        if records is not None:
            yield from (r for r in records if isinstance(r, dict))


def discover_targets(reports):
    """Use only observed account/client IDs; never enumerate guessed identifiers."""
    service, users, clients = set(), set(), set()
    skipped = 0

    def add(target, value):
        nonlocal skipped
        if value is None:
            return
        if valid_identifier(value):
            target.add(value)
        else:
            skipped += 1

    for report in reports:
        for record in iter_records(report):
            operation = report["operation"]
            if operation == "service-accounts":
                add(service, record.get("atlassianId", record.get("id")))
            if operation == "managed-accounts":
                add(users, record.get("account_id"))
            user = record.get("user")
            if isinstance(user, dict):
                add(users, user.get("id"))
                if operation == "service-account-api-tokens":
                    add(service, user.get("id"))
            for field in ("serviceAccount", "createdBy"):
                account = record.get(field)
                if isinstance(account, dict):
                    add(users, account.get("id"))
                    if field == "serviceAccount":
                        add(service, account.get("id"))
            if "oauth-clients" in operation:
                add(clients, record.get("clientId"))
    users.update(service)
    return {
        "service_account_ids": sorted(service),
        "user_ids": sorted(users),
        "oauth_client_ids": sorted(clients),
        "invalid_identifiers": skipped,
    }


def count_comparisons(reports):
    """Counts are supporting observations, never proof of complete coverage."""
    by_op = {r["operation"]: r for r in reports if "target_id" not in r}
    comparisons = []
    for listing, count_op, id_field in (
        ("admin-api-keys", "admin-api-key-count", "id"),
        ("org-api-tokens", "org-api-token-count", "id"),
    ):
        source, count = by_op.get(listing), by_op.get(count_op)
        if not source or not count or not count["pages"]:
            continue
        value = count["pages"][-1]["metadata"]
        if isinstance(value, dict):
            value = value.get("total")
        ids = {r[id_field] for r in iter_records(source) if isinstance(r.get(id_field), str)}
        observed = value if type(value) is int and value >= 0 else None
        comparisons.append(
            {
                "listing": listing,
                "count_operation": count_op,
                "listed_unique_ids": len(ids),
                "reported_count": observed,
                "equal_at_observation": observed == len(ids) if observed is not None else None,
                "proves_completeness": False,
            }
        )
    source = by_op.get("org-oauth-clients")
    batches = [r for r in reports if r["operation"] == "org-oauth-client-count"]
    if source and batches:
        # Compare only the requested account scope, never an org-wide total.
        requested, counts = set(), {}
        valid = True
        for batch in batches:
            ids = batch.get("requested_account_ids", [])
            if not ids or requested.intersection(ids):
                valid = False
            requested.update(ids)
            if batch["coverage"] != "complete" or len(batch["pages"]) != 1:
                valid = False
                continue
            body = batch["pages"][0]["metadata"]
            if not valid_scalar_shape("account_counts", body):
                valid = False
                continue
            rows = body["validServiceAccountIds"]
            returned = [row["serviceAccountId"] for row in rows]
            if (
                body["invalidServiceAccountIds"]
                or len(returned) != len(set(returned))
                or set(returned) != set(ids)
            ):
                valid = False
            counts.update((row["serviceAccountId"], row["credentialsCount"]) for row in rows)
        listed = set()
        attributed = True
        for row in iter_records(source):
            account = row.get("serviceAccount")
            account_id = account.get("id") if isinstance(account, dict) else None
            if not valid_identifier(account_id) or not valid_identifier(row.get("clientId")):
                attributed = False
            elif account_id in requested:
                listed.add(row["clientId"])
        observed = sum(counts.values()) if valid and set(counts) == requested else None
        comparisons.append(
            {
                "listing": "org-oauth-clients",
                "count_operation": "org-oauth-client-count",
                "comparison_scope": "requested_service_accounts",
                "requested_account_count": len(requested),
                "listed_unique_ids": len(listed),
                "reported_count": observed,
                "equal_at_observation": observed == len(listed)
                if observed is not None and attributed
                else None,
                "proves_completeness": False,
            }
        )
    return comparisons


def collect_discovery(client, *, max_targets=50, include_account_reads=True, now=utc_now):
    return consume(
        iter_discovery(
            client, max_targets=max_targets, include_account_reads=include_account_reads, now=now
        )
    )


def iter_discovery(client, *, max_targets=50, include_account_reads=True, now=utc_now):
    if type(max_targets) is not int or not 1 <= max_targets <= 500:
        raise ValueError("Invalid target limit")
    if type(include_account_reads) is not bool:
        raise ValueError("Invalid account read selection")
    started = now()
    disabled = [] if include_account_reads else ["managed-accounts", *ACCOUNT_DETAIL_OPERATIONS]
    reports = []
    for op in STATIC_OPERATIONS:
        if op not in disabled:
            reports.append((yield from iter_operation(client, op, now=now)))
    targets = discover_targets(reports)
    omitted = {}
    for kind in ("service_account_ids", "user_ids", "oauth_client_ids"):
        omitted[kind] = max(0, len(targets[kind]) - max_targets)
        targets[kind] = targets[kind][:max_targets]
    short_service_ids = [value for value in targets["service_account_ids"] if len(value) <= 100]
    skipped_count_ids = len(targets["service_account_ids"]) - len(short_service_ids)
    for start in range(0, len(short_service_ids), 100):
        for operation in ACCOUNT_COUNT_OPERATIONS:
            reports.append(
                (
                    yield from iter_operation(
                        client,
                        operation,
                        body=short_service_ids[start : start + 100],
                        now=now,
                    )
                )
            )
    for identifier in targets["service_account_ids"]:
        for op in (
            "service-account-api-tokens-by-account",
            "service-account-oauth-clients-by-account",
        ):
            reports.append((yield from iter_operation(client, op, identifier=identifier, now=now)))
    for identifier in targets["oauth_client_ids"]:
        reports.append(
            (
                yield from iter_operation(
                    client, "oauth-client-detail", identifier=identifier, now=now
                )
            )
        )
    for identifier in targets["user_ids"] if include_account_reads else ():
        for op in ("user-management-permissions", "user-profile", "user-api-tokens"):
            reports.append((yield from iter_operation(client, op, identifier=identifier, now=now)))
    blocked = [
        op
        for op, ids in (
            ("service-account-token-counts", short_service_ids),
            ("org-oauth-client-count", short_service_ids),
            ("service-account-api-tokens-by-account", targets["service_account_ids"]),
            ("service-account-oauth-clients-by-account", targets["service_account_ids"]),
            ("oauth-client-detail", targets["oauth_client_ids"]),
            ("user-management-permissions", targets["user_ids"]),
            ("user-profile", targets["user_ids"]),
            ("user-api-tokens", targets["user_ids"]),
        )
        if not ids and op not in disabled
    ]
    states = [r["coverage"] for r in reports]
    status = (
        "complete"
        if all(s == "complete" for s in states)
        and not any(omitted.values())
        and not blocked
        and not targets["invalid_identifiers"]
        and not skipped_count_ids
        else "unverified"
    )
    if any(s in ("partial", "failed") for s in states):
        status = "partial" if any(r["pages"] for r in reports) else "failed"
    return {
        "schema_version": 1,
        "report_type": "metadata_discovery",
        "provider": "atlassian",
        "environment": "cloud",
        "queried_org_id": client.org_id,
        "started_at": started,
        "finished_at": now(),
        "inventory_complete": False,
        "run_status": status,
        "limits": {
            **asdict(client.limits),
            "max_targets_per_kind": max_targets,
            "org_api_tokens_page_size": getattr(client, "token_page_size", 20),
        },
        "target_discovery": targets,
        "targets_omitted_by_limit": omitted,
        "count_ids_exceeding_contract_limit": skipped_count_ids,
        "not_requested_no_observed_targets": blocked,
        "not_requested_by_configuration": disabled,
        "collections": reports,
        "count_comparisons": count_comparisons(reports),
    }


def collect_accounts(client, *, max_targets=50, now=utc_now):
    return consume(iter_accounts(client, max_targets=max_targets, now=now))


def iter_accounts(client, *, max_targets=50, now=utc_now):
    """Use a separate connection for managed accounts and their three GET reads.

    Only account_id values from this organization's managed-account listing are
    eligible. Nested creator or unrelated user IDs do not expand this scope.
    """
    if type(max_targets) is not int or not 1 <= max_targets <= 500:
        raise ValueError("Invalid target limit")
    started = now()
    listing = yield from iter_operation(client, "managed-accounts", now=now)
    reports, observed, invalid = [listing], set(), 0
    for page in listing["pages"]:
        rows, _ = collection_records(READ_OPERATIONS["managed-accounts"], page["metadata"])
        for record in rows or []:
            value = record.get("account_id") if isinstance(record, dict) else None
            if valid_identifier(value):
                observed.add(value)
            else:
                invalid += 1
    users = sorted(observed)[:max_targets]
    omitted = max(0, len(observed) - len(users))
    for identifier in users:
        for operation in ACCOUNT_DETAIL_OPERATIONS:
            reports.append(
                (yield from iter_operation(client, operation, identifier=identifier, now=now))
            )
    states = [report["coverage"] for report in reports]
    status = "complete"
    if any(state in ("partial", "failed") for state in states):
        status = "partial" if any(report["pages"] for report in reports) else "failed"
    elif any(state != "complete" for state in states) or invalid or omitted or not users:
        status = "unverified"
    return {
        "schema_version": 1,
        "report_type": "managed_account_metadata_discovery",
        "provider": "atlassian",
        "environment": "cloud",
        "queried_org_id": client.org_id,
        "started_at": started,
        "finished_at": now(),
        "inventory_complete": False,
        "run_status": status,
        "limits": {**asdict(client.limits), "max_targets_per_kind": max_targets},
        "target_discovery": {
            "service_account_ids": [],
            "user_ids": users,
            "oauth_client_ids": [],
            "invalid_identifiers": invalid,
        },
        "targets_omitted_by_limit": {
            "service_account_ids": 0,
            "user_ids": omitted,
            "oauth_client_ids": 0,
        },
        "count_ids_exceeding_contract_limit": 0,
        "not_requested_no_observed_targets": [] if users else list(ACCOUNT_DETAIL_OPERATIONS),
        "collections": reports,
        "count_comparisons": [],
    }


def discovery_summary(result):
    """Only fixed operation names and metrics. Metadata and field paths stay private."""
    summary = {
        "report_type": result["report_type"],
        "schema_version": result["schema_version"],
        "run_status": result["run_status"],
        "inventory_complete": False,
        "request_count": sum(r["requests"] for r in result["collections"]),
        "response_pages": sum(len(r["pages"]) for r in result["collections"]),
        "observed_target_counts": {
            kind: len(result["target_discovery"][kind])
            for kind in ("service_account_ids", "user_ids", "oauth_client_ids")
        },
        "invalid_identifier_count": result["target_discovery"]["invalid_identifiers"],
        "count_ids_exceeding_contract_limit": result["count_ids_exceeding_contract_limit"],
        "targets_omitted_by_limit": result["targets_omitted_by_limit"],
        "not_requested_no_observed_targets": result["not_requested_no_observed_targets"],
        "not_requested_by_configuration": result.get("not_requested_by_configuration", []),
        "count_comparisons": result["count_comparisons"],
        "operations": {},
    }
    for report in result["collections"]:
        item = summary["operations"].setdefault(
            report["operation"],
            {
                "calls": 0,
                "requests": 0,
                "pages": 0,
                "saved_records": 0,
                "coverage_counts": {},
                "http_status_counts": {},
                "reason_counts": {},
                "redactions": {},
            },
        )
        item["calls"] += 1
        item["requests"] += report["requests"]
        item["pages"] += len(report["pages"])
        item["saved_records"] += report["saved_records"]
        for name, value in (
            ("coverage_counts", report["coverage"]),
            ("http_status_counts", report["last_http_status"]),
            ("reason_counts", report["reason"]),
        ):
            if value is not None:
                item[name][str(value)] = item[name].get(str(value), 0) + 1
        item["redactions"] = dict(Counter(item["redactions"]) + Counter(report["redactions"]))
        item["record_quality"] = dict(
            Counter(item.get("record_quality", {})) + Counter(report.get("record_quality", {}))
        )
    return summary
