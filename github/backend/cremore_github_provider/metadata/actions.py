"""GitHub Actions secret names and storage scope, never secret values."""

from __future__ import annotations

import re
from urllib.parse import quote

from cremore.coverage.metadata_models import metadata_text, timestamp

from .endpoints import EndpointError
from .projection import SHORT_REPO_FIELDS, pick, repository_metadata, require_id, slug

SECRET_SOURCES = ("org_actions_secrets", "repo_actions_secrets", "environment_actions_secrets")
ACTION_TASKS = {*SECRET_SOURCES, "repo_environments", "org_secret_repositories"}
SECRET_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,255}")


def secret_name(value):
    if not isinstance(value, str) or not SECRET_NAME.fullmatch(value):
        raise EndpointError("invalid_actions_secret_name")
    return metadata_text(value)


def environment_name(value):
    if not isinstance(value, str) or not value or len(value) > 255 or value in (".", ".."):
        raise EndpointError("invalid_actions_environment_name")
    return metadata_text(value)


def task_path(current):
    org, kind, context = slug(current.get("org")), current["kind"], current.get("context") or {}
    if kind == "org_actions_secrets":
        return f"/orgs/{org}/actions/secrets", "secrets"
    if kind == "org_secret_repositories":
        return f"/orgs/{org}/actions/secrets/{secret_name(context.get('secret_name'))}/repositories", "repositories"
    repo = repository_metadata(context.get("repository"), org, fields=SHORT_REPO_FIELDS, shallow=True)
    base = f"/repos/{org}/{repo['name']}"
    if kind == "repo_actions_secrets":
        return base + "/actions/secrets", "secrets"
    if kind == "repo_environments":
        return base + "/environments", "environments"
    name = quote(environment_name(context.get("environment")), safe="")
    return base + f"/environments/{name}/secrets", "secrets"


def validate_task(current):
    path, key = task_path(current)
    if (current.get("path") != path or current.get("collection_key") != key
            or current.get("auth") != "org" or current.get("paginated") is not True):
        raise EndpointError("invalid_actions_metadata_task")


def _dated(row, fields):
    result = pick(row, fields)
    for field in ("created_at", "updated_at"):
        if not isinstance(row.get(field), str):
            raise EndpointError("invalid_actions_metadata_time")
        try:
            result[field] = timestamp(row[field])
        except ValueError:
            raise EndpointError("invalid_actions_metadata_time") from None
    return result


def secret_metadata(row, current):
    kind, context = current["kind"], current.get("context") or {}
    result = _dated(row, ("name", "created_at", "updated_at"))
    result["name"] = secret_name(row.get("name"))
    result["org"] = current["org"]
    result["resource_type"] = {"org_actions_secrets": "organization", "repo_actions_secrets": "repository",
                               "environment_actions_secrets": "environment"}[kind]
    if kind == "org_actions_secrets":
        if row.get("visibility") not in {"all", "private", "selected"}:
            raise EndpointError("invalid_actions_secret_visibility")
        result["visibility"] = row["visibility"]
    else:
        result["full_name"] = context["repository"]["full_name"]
        if kind == "environment_actions_secrets":
            result["environment"] = environment_name(context["environment"])
    # value, encrypted_value and remote URLs are never projected or followed.
    return result


def secret_object_id(values):
    scope = values["org"] if values["resource_type"] == "organization" else values["full_name"]
    env = ":" + quote(values["environment"], safe="") if "environment" in values else ""
    return "actionsSecret:" + values["resource_type"] + ":" + scope + env + ":" + values["name"]


def handle_page(current, data):
    from .pages import task

    validate_task(current)
    key = current["collection_key"]
    if (not isinstance(data, dict) or type(data.get("total_count")) is not int
            or not 0 <= data["total_count"] <= 10000000 or not isinstance(data.get(key), list)
            or not all(isinstance(row, dict) for row in data[key]) or len(data[key]) > data["total_count"]):
        raise EndpointError("invalid_actions_metadata_page")
    rows, kind = data[key], current["kind"]
    output = {"inventory_items": [], "reports": [], "contexts": [], "tasks": [], "vault_items": [],
              "expected_count": data["total_count"], "received_count": len(rows)}
    context = current.get("context") or {}
    if kind in SECRET_SOURCES:
        for row in rows:
            values = secret_metadata(row, current)
            output["vault_items"].append(values)
            if values.get("visibility") == "selected":
                output["tasks"].append(task(current["enterprise"], current["org"], "org_secret_repositories",
                    f"/orgs/{current['org']}/actions/secrets/{values['name']}/repositories",
                    collection_key="repositories", context={"secret_name": values["name"]}, priority=65))
    elif kind == "repo_environments":
        for row in rows:
            require_id(row.get("id"))
            name = environment_name(row.get("name"))
            projected = _dated(row, ("id", "name", "created_at", "updated_at"))
            projected.update(org=current["org"], full_name=context["repository"]["full_name"])
            output["contexts"].append({"kind": "actions_environment", "external_id": row["id"], "metadata": projected})
            child = task(current["enterprise"], current["org"], "environment_actions_secrets", "",
                         collection_key="secrets", context={**context, "environment": name}, priority=65)
            child["path"] = task_path(child)[0]
            output["tasks"].append(child)
    else:
        repositories = [repository_metadata(row, current["org"]) for row in rows]
        output["secret_repositories"] = repositories
    return output
