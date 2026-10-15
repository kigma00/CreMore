"""The exact read paths this provider may request, and how a page may advance.

Both teammate programs restricted themselves to a fixed list of documented GET
routes; that list is preserved here, parameterised by the connection's own
enterprise and organization scopes instead of one hard-coded enterprise. A
pagination link may move the cursor and nothing else: not the host, not the
path, not the search scope.
"""

from __future__ import annotations

import re
from urllib.parse import parse_qs, urlencode, urlsplit

ORG = r"[A-Za-z0-9][A-Za-z0-9-]{0,38}"
REPO = r"[A-Za-z0-9_.-]{1,100}"
ENVIRONMENT = r"(?:[A-Za-z0-9_.~-]|%[0-9A-F]{2}){1,3060}"
CURSORS = {"after", "before", "page"}
INVENTORY_FLAGS = ("incomplete-results", "truncated", "sources-unavailable",
                   "metadata-incomplete", "expiry-incomplete")


class EndpointError(ValueError):
    """A path or link outside the approved read surface."""


def read_paths(enterprise=""):
    patterns = [
        # The App's own identity and installation list, read with the App JWT.
        r"/app", r"/app/installations",
        r"/orgs/" + ORG + r"/(?:installation|installations|credential-authorizations|audit-log)",
        r"/orgs/" + ORG + r"/personal-access-token(?:s|-requests)(?:/[1-9][0-9]*/repositories)?",
        r"/orgs/" + ORG + r"/actions/permissions/workflow",
        r"/orgs/" + ORG + r"/actions/secrets(?:/[A-Za-z_][A-Za-z0-9_]{0,255}/repositories)?",
        r"/installation/repositories",
        r"/repos/" + ORG + "/" + REPO
        + r"/(?:keys|actions/permissions(?:/workflow|/fork-pr-workflows-private-repos)?)",
        r"/repos/" + ORG + "/" + REPO + r"/actions/runs",
        r"/repos/" + ORG + "/" + REPO + r"/actions/secrets",
        r"/repos/" + ORG + "/" + REPO + r"/environments(?:/" + ENVIRONMENT + r"/secrets)?",
        r"/repos/" + ORG + "/" + REPO + r"/actions/runs/[1-9][0-9]*/attempts/[1-9][0-9]*/jobs",
    ]
    if enterprise:
        base = "/enterprises/" + re.escape(enterprise)
        patterns[0:0] = [
            base + r"/(?:installation|credentials|audit-log)",
            base + r"/credentials/exports/[A-Za-z0-9_-]{1,200}",
            base + r"/apps/installable_organizations(?:/" + ORG + r"/accessible_repositories)?",
            base + r"/apps/organizations/" + ORG + r"/installations(?:/[1-9][0-9]*/repositories)?",
        ]
    return tuple(patterns)


def validate_operation(method, path, *, enterprise="", allow_token_issue=True, allow_export_create=False):
    """Documented reads, token issuance, and an explicitly requested inventory export."""
    parsed = urlsplit(path)
    if (parsed.scheme or parsed.netloc or parsed.fragment or len(path) > 16384
            or any(part in (".", "..") for part in parsed.path.split("/"))
            or not re.fullmatch(r"[A-Za-z0-9_%+.,:~=&*-]*", parsed.query)):
        raise EndpointError("invalid_github_operation")
    if method == "POST":
        if (allow_export_create and enterprise and not parsed.query
                and parsed.path == f"/enterprises/{enterprise}/credentials/exports"):
            return parsed.path
        if (not allow_token_issue
                or not re.fullmatch(r"/app/installations/[1-9][0-9]*/access_tokens", parsed.path)
                or parsed.query):
            raise EndpointError("write_operation_refused")
        return parsed.path
    if method != "GET":
        raise EndpointError("write_operation_refused")
    if not any(re.fullmatch(pattern, parsed.path) for pattern in read_paths(enterprise)):
        raise EndpointError("unlisted_read_endpoint")
    return parsed.path


def first_path(path, *, paginated=True, page_size=100):
    if not paginated or "per_page=" in path:
        return path
    return path + ("&" if "?" in path else "?") + urlencode({"per_page": page_size})


def next_path(current, link, *, api):
    """A next link may change only the cursor, never host, path or scope.

    ``api`` is the connection's own API base, so a GHES or ghe.com link is
    accepted on its own host and a link to any other host is not.
    """
    if not link:
        return None
    if not isinstance(link, str) or len(link) > 32768:
        raise EndpointError("invalid_pagination_link")
    matches = []
    for part in link.split(","):
        entry = re.fullmatch(r'\s*<([^<>]+)>\s*;\s*rel=(?:"([^"]+)"|([A-Za-z ]+))\s*', part)
        if not entry:
            raise EndpointError("invalid_pagination_link")
        if "next" in (entry.group(2) or entry.group(3)).split():
            matches.append(entry.group(1))
    if not matches:
        return None
    if len(matches) != 1:
        raise EndpointError("invalid_pagination_link")
    target, source, base = urlsplit(matches[0]), urlsplit(current), urlsplit(api)
    prefix = base.path.rstrip("/")
    if (target.scheme != "https" or target.fragment or target.username or target.password
            or target.netloc != base.netloc or not target.path.startswith(prefix + "/")
            or not _same_resource(target.path[len(prefix):], source.path)):
        raise EndpointError("unsafe_pagination_link")
    old = parse_qs(source.query, keep_blank_values=True, max_num_fields=20)
    new = parse_qs(target.query, keep_blank_values=True, max_num_fields=20)
    if any(len(values) != 1 for values in new.values()):
        raise EndpointError("invalid_pagination_link")
    cursors = set(new) & CURSORS
    # The audit log documents its next link as after=<cursor>&before= (both
    # present, before empty); every other list moves exactly one cursor.
    audit_pair = source.path.endswith("/audit-log") and cursors == {"after", "before"}
    if set(new) - set(old) - CURSORS or not (len(cursors) == 1 or audit_pair):
        raise EndpointError("invalid_pagination_link")
    for key in set(old) - CURSORS:
        if key in new and new[key] != old[key]:
            raise EndpointError("pagination_scope_changed")
    params = {key: values[0] for key, values in old.items() if key not in CURSORS}
    params.update({key: new[key][0] for key in CURSORS if key in new})
    result = source.path + "?" + urlencode(params)
    if result == current:
        raise EndpointError("pagination_not_advancing")
    return result


# GitHub may name the scope by numeric ID in a next link (/enterprises/13827/audit-log
# for /enterprises/acme/audit-log). The request keeps its own path; only the cursor moves.
_NUMBERED = ((r"/enterprises/[^/]+", "/enterprises/"), (r"/orgs/[^/]+", "/organizations/"),
             (r"/repos/[^/]+/[^/]+", "/repositories/"))


def _same_resource(link_path, path):
    if link_path == path:
        return True
    for named, numbered in _NUMBERED:
        scope = re.match(named, path)
        if scope:
            return re.fullmatch(re.escape(numbered) + r"[1-9][0-9]*" + re.escape(path[scope.end():]),
                                link_path) is not None
    return False


def validate_inventory_page(items):
    """Required API fields cannot silently turn malformed rows into inventory."""
    text_fields = ("inventory_id", "credential_type", "item_type", "credential_state",
                   "authorization_state", "effective_access_state")
    for item in items:
        if any(not isinstance(item.get(key), str) or not item[key] or len(item[key]) > 2048
               for key in text_fields):
            raise EndpointError("invalid_inventory_record")
        if len(item["inventory_id"]) > 2000:
            raise EndpointError("invalid_inventory_identifier")
        if (item["item_type"] not in ("credential", "token_issuer_principal")
                or item["credential_state"] not in ("active", "expired", "revoked", "deleted")
                or item["authorization_state"] not in ("currently_authorized", "member_owned_only")
                or item["effective_access_state"] not in ("effective", "not_effective", "unknown")
                or type(item.get("enterprise_authorized")) is not bool
                or type(item.get("authorization_count")) is not int
                or item["authorization_count"] < 0
                or not isinstance(item.get("authorized_organizations"), list)):
            raise EndpointError("invalid_inventory_record")
        for organization in item["authorized_organizations"]:
            if (not isinstance(organization, dict)
                    or type(organization.get("id")) is not int or organization["id"] <= 0
                    or not isinstance(organization.get("login"), str)
                    or not re.fullmatch(ORG, organization["login"])):
                raise EndpointError("invalid_inventory_record")


def validate_audit_page(items, enterprise, org=None):
    for item in items:
        action = item.get("action")
        if not isinstance(action, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,200}", action):
            raise EndpointError("invalid_audit_record")
        if (enterprise and item.get("business") is not None
                and (not isinstance(item["business"], str)
                     or item["business"].lower() != enterprise.lower())):
            raise EndpointError("audit_scope_mismatch")
        if org and item.get("org") is not None and (
                not isinstance(item["org"], str) or item["org"].lower() != org.lower()):
            raise EndpointError("audit_scope_mismatch")


def inventory_flags(headers):
    """The Enterprise inventory's own completeness headers, kept as warnings."""
    from datetime import UTC, datetime

    flags, generated_at = [], None
    for flag in INVENTORY_FLAGS:
        value = headers.get("x-github-enterprise-credentials-" + flag)
        if value and str(value).lower() not in ("false", "0", ""):
            warning = flag + ":" + str(value)[:500]
            if warning not in flags:
                flags.append(warning)
    generated = headers.get("x-github-enterprise-credentials-generated-at")
    if generated:
        try:
            if not isinstance(generated, str) or len(generated) > 100:
                raise ValueError
            parsed = datetime.fromisoformat(generated)
            if parsed.tzinfo is None:
                raise ValueError
            generated_at = parsed.astimezone(UTC).isoformat()
        except (ValueError, TypeError):
            flags.append("generated-at:invalid")
    return flags, generated_at
