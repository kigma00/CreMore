"""Pure page adapters: project one response and seed the tasks it implies.

These functions make no requests and hold no secrets. One page is evidence, not
a declaration that an organization is fully scanned -- the engine decides
completeness from its own task states. The organization sources, the Enterprise
inventory and audit, and the Actions run context all pass through here.
"""

from __future__ import annotations

from copy import deepcopy
from urllib.parse import urlencode

from .actions import ACTION_TASKS, SECRET_SOURCES
from .endpoints import (
    EndpointError,
    inventory_flags,
    validate_audit_page,
    validate_inventory_page,
)
from .projection import (
    ACTIONS_POLICY,
    ENTERPRISE_INSTALLATION_FIELDS,
    FORK_POLICY,
    PAT_FIELDS,
    REQUEST_FIELDS,
    SHORT_REPO_FIELDS,
    SSO_FIELDS,
    SSO_TYPES,
    WORKFLOW_POLICY,
    deploy_key_metadata,
    job_metadata,
    pick,
    policy_metadata,
    project_installation,
    project_pat,
    repository_metadata,
    require_id,
    run_metadata,
    slug,
)

ORG_SOURCES = ("org_sso", "org_fgpat", "org_pat_requests", "org_installations",
               "org_repositories", "org_workflow_policy")
ENTERPRISE_SOURCES = ("enterprise_org_installations", "enterprise_org_repositories")
ACTIONS_SOURCES = ("repo_actions_runs", *SECRET_SOURCES)


def task(enterprise, org, kind, path, *, auth="org", paginated=True, collection_key=None,
         context=None, priority=50):
    return {"kind": kind, "scope": org, "org": org, "enterprise": enterprise, "auth": auth,
            "path": path, "paginated": paginated, "collection_key": collection_key,
            "context": deepcopy(context or {}), "priority": priority}


def seed_org_tasks(enterprise, org, *, sources=(), include_actions=False, server=False):
    """Every applicable source for one organization; the engine marks refusals.

    An Enterprise-installed App can read enterprise organization installation
    context. Organization and repository endpoints need an organization token
    that is verified separately, so they are their own tasks. A Server's API has
    no SAML SSO credential authorizations, so its default reads leave them out
    (named in ``sources``, they are still asked for).
    """
    org = slug(org)
    available = []
    if enterprise:
        base = f"/enterprises/{slug(enterprise)}/apps"
        available += [
            task(enterprise, org, "enterprise_org_installations",
                 f"{base}/organizations/{org}/installations", auth="enterprise", priority=30),
            task(enterprise, org, "enterprise_org_repositories",
                 f"{base}/installable_organizations/{org}/accessible_repositories",
                 auth="enterprise", priority=35),
        ]
    available += [
        task(enterprise, org, "org_sso", f"/orgs/{org}/credential-authorizations", priority=40),
        task(enterprise, org, "org_fgpat", f"/orgs/{org}/personal-access-tokens", priority=41),
        task(enterprise, org, "org_pat_requests", f"/orgs/{org}/personal-access-token-requests",
             priority=42),
        task(enterprise, org, "org_installations", f"/orgs/{org}/installations",
             collection_key="installations", priority=43),
        task(enterprise, org, "org_repositories", "/installation/repositories",
             collection_key="repositories", priority=44),
        task(enterprise, org, "org_workflow_policy", f"/orgs/{org}/actions/permissions/workflow",
             paginated=False, priority=45),
        task(enterprise, org, "org_actions_secrets", f"/orgs/{org}/actions/secrets",
             collection_key="secrets", priority=46),
    ]
    chosen = [item for item in available if item["kind"] in sources or not sources and item["kind"] not in SECRET_SOURCES
              and not (server and item["kind"] == "org_sso")]
    needs_repositories = include_actions or set(sources) & {"repo_actions_runs", "repo_actions_secrets", "environment_actions_secrets"}
    if needs_repositories and not any(item["kind"] == "org_repositories" for item in chosen):
        chosen.append(next(item for item in available if item["kind"] == "org_repositories"))
    return chosen


# What each repository of a repository list is read for: path suffix and paging.
REPOSITORY_READS = {"repo_deploy_keys": ("/keys", True),
                    "repo_workflow_policy": ("/actions/permissions/workflow", False),
                    "repo_actions_policy": ("/actions/permissions", False),
                    "repo_fork_policy": ("/actions/permissions/fork-pr-workflows-private-repos", False),
                    "repo_actions_runs": ("/actions/runs", True),
                    "repo_actions_secrets": ("/actions/secrets", True),
                    "repo_environments": ("/environments", True)}


def repository_read_kinds(options):
    """The reads each listed repository is given under these options, in order."""
    options = options or {}
    sources = set(options.get("sources") or ())
    kinds = [] if sources and "org_repositories" not in sources and not options.get("include_actions") else [
        "repo_deploy_keys", "repo_workflow_policy", "repo_actions_policy", "repo_fork_policy"]
    if options.get("include_actions") or "repo_actions_runs" in sources:
        kinds.append("repo_actions_runs")
    if "repo_actions_secrets" in sources:
        kinds.append("repo_actions_secrets")
    if "environment_actions_secrets" in sources:
        kinds.append("repo_environments")
    return kinds


def audit_path(scope, window, *, enterprise=False, include="web"):
    base = f"/enterprises/{slug(scope)}" if enterprise else "/orgs/" + slug(scope)
    return base + "/audit-log?" + urlencode(
        {"include": include, "order": "asc",
         "phrase": "created:" + window[0] + ".." + window[1]})


def _report(current, results):
    results = deepcopy(results)
    for result in results.values():
        result.update(org=current["org"], source_endpoint=current["path"], complete=False,
                      error=None, page_evidence=True)
    return {"org": current["org"], "results": results, "requested_collectors": list(results),
            "complete": False, "page_evidence": True}


def _context(current, kind, external_id, metadata):
    return {"kind": kind, "scope": current["org"], "org": current["org"],
            "external_id": str(external_id), "source_endpoint": current["path"],
            "metadata": deepcopy(metadata)}


def _rows(current, data):
    # A missing collection key or a malformed success body is never silently
    # treated as an empty list.
    if isinstance(data, dict) and current.get("collection_key"):
        data = data.get(current["collection_key"])
    if not isinstance(data, list) or not all(isinstance(row, dict) for row in data):
        raise EndpointError("unexpected_supplemental_response_shape")
    return data


def _validate_task(current, options):
    if not isinstance(current, dict):
        raise EndpointError("invalid_supplemental_task")
    org = slug(current.get("org"))
    enterprise = current.get("enterprise") or ""
    if current.get("scope") != org or current.get("auth") not in {"org", "enterprise"}:
        raise EndpointError("invalid_supplemental_task_scope")
    kind = current.get("kind")
    if kind in ACTION_TASKS:
        from .actions import validate_task

        validate_task(current)
        return
    seeds = {item["kind"]: item for item in seed_org_tasks(enterprise, org)}
    if kind in seeds:
        expected = seeds[kind]
        if any(current.get(key) != expected[key]
               for key in ("path", "auth", "paginated", "collection_key")):
            raise EndpointError("invalid_supplemental_task_endpoint")
        return
    context = current.get("context")
    if not isinstance(context, dict):
        raise EndpointError("invalid_supplemental_task_context")
    if kind in {"org_fgpat_repositories", "org_pat_request_repositories"}:
        parent = context.get("credential")
        if not isinstance(parent, dict):
            raise EndpointError("invalid_supplemental_task_context")
        record_id = require_id(parent.get("id"))
        resource = ("personal-access-tokens" if kind == "org_fgpat_repositories"
                    else "personal-access-token-requests")
        path, auth, paginated = f"/orgs/{org}/{resource}/{record_id}/repositories", "org", True
    elif kind == "enterprise_installation_repositories":
        install_id = require_id(context.get("installation_id"))
        path = (f"/enterprises/{slug(enterprise)}/apps/organizations/{org}"
                f"/installations/{install_id}/repositories")
        auth, paginated = "enterprise", True
    elif kind in {"repo_deploy_keys", "repo_workflow_policy", "repo_actions_policy",
                  "repo_fork_policy", "repo_actions_runs"}:
        repo = repository_metadata(context.get("repository"), org, fields=SHORT_REPO_FIELDS,
                                   shallow=True)
        suffix = {"repo_deploy_keys": "/keys",
                  "repo_workflow_policy": "/actions/permissions/workflow",
                  "repo_actions_policy": "/actions/permissions",
                  "repo_fork_policy": "/actions/permissions/fork-pr-workflows-private-repos",
                  "repo_actions_runs": "/actions/runs"}[kind]
        path = f"/repos/{org}/{repo['name']}{suffix}"
        auth = "org"
        paginated = kind in {"repo_deploy_keys", "repo_actions_runs"}
        if kind == "repo_actions_runs" and options is not None:
            path += "?" + urlencode({"created": options["run_window"]})
    elif kind == "run_jobs":
        run = context.get("run")
        repo = repository_metadata(context.get("repository"), org, fields=SHORT_REPO_FIELDS,
                                   shallow=True)
        if not isinstance(run, dict):
            raise EndpointError("invalid_supplemental_task_context")
        path = (f"/repos/{org}/{repo['name']}/actions/runs/{require_id(run.get('id'))}"
                f"/attempts/{require_id(run.get('run_attempt'))}/jobs")
        auth, paginated = "org", True
    else:
        raise EndpointError("unknown_supplemental_task_kind")
    if (current.get("path", "").split("?", 1)[0] != path.split("?", 1)[0]
            or current.get("auth") != auth or current.get("paginated") is not paginated
            or current.get("collection_key") is not None):
        raise EndpointError("invalid_supplemental_task_endpoint")


def handle_page(current, data, *, options=None):
    """Project one successful page and produce deterministic follow-up tasks.

    ``inventory_items`` is reserved for canonical Enterprise inventory; these
    sources use reports and contexts so a policy or installation record can
    never become an issued token.
    """
    _validate_task(current, options)
    if current["kind"] in ACTION_TASKS:
        from .actions import handle_page as actions_page

        return actions_page(current, data)
    output = {"inventory_items": [], "reports": [], "contexts": [], "tasks": []}
    org, enterprise, kind = current["org"], current["enterprise"], current["kind"]
    context = current.get("context") or {}
    if kind.endswith("_policy"):
        schema = (WORKFLOW_POLICY if kind in {"org_workflow_policy", "repo_workflow_policy"}
                  else ACTIONS_POLICY if kind == "repo_actions_policy" else FORK_POLICY)
        policy = policy_metadata(data, schema)
        if kind == "org_workflow_policy":
            result = {"organization_workflow_permissions": policy, "repositories": []}
        else:
            field = {"repo_workflow_policy": "workflow_permissions",
                     "repo_actions_policy": "actions_permissions",
                     "repo_fork_policy": "fork_pr_workflow_settings"}[kind]
            result = {"repositories": [{"repository": context["repository"], field: policy}]}
        result["source"] = "github_actions_token_policy_context"
        output["reports"].append(_report(current, {"github_token": result}))
        output["contexts"].append(_context(current, "actions_policy", current["path"], policy))
        return output
    if kind == "repo_actions_runs":
        # A runs or jobs response is an object, not a list, so it is projected
        # before the shared list guard.
        repo = context["repository"]
        runs = [run_metadata(row, repo) for row in _runs(data)]
        # Each run is recorded once, from the report below, keyed by repository and attempt.
        for run in runs:
            output["tasks"].append(task(
                enterprise, org, "run_jobs",
                f"/repos/{org}/{repo['name']}/actions/runs/{run['id']}"
                f"/attempts/{run['run_attempt']}/jobs",
                context={"repository": repo, "run": run}, priority=70))
        output["reports"].append(_report(current, {"github_token": {
            "source": "github_actions_token_policy_and_run_context",
            "repositories": [{"repository": repo, "workflow_runs": runs}]}}))
    elif kind == "run_jobs":
        run = context["run"]
        jobs = [job_metadata(row, run) for row in _jobs(data)]
        output["reports"].append(_report(current, {"github_token": {
            "source": "github_actions_token_policy_and_run_context",
            "repositories": [{"repository": context["repository"],
                              "workflow_runs": [{**run, "jobs": jobs}]}]}}))
    if kind in ("repo_actions_runs", "run_jobs"):
        return output
    rows = _rows(current, data)
    if kind == "org_sso":
        results = {collector: {"source": "organization_saml_sso_authorizations", field: []}
                   for collector, field, _fields in SSO_TYPES.values()}
        for row in rows:
            if not isinstance(row.get("credential_type"), str):
                raise EndpointError("unexpected_sso_credential_type")
            mapping = SSO_TYPES.get(row["credential_type"])
            if mapping:
                collector, field, fields = mapping
                results[collector][field].append(pick(row, fields))
            else:
                output["contexts"].append(_context(
                    current, "unclassified_sso_authorization",
                    str(row.get("credential_id", "unknown")), pick(row, SSO_FIELDS)))
        output["reports"].append(_report(current, results))
    elif kind in {"org_fgpat", "org_pat_requests"}:
        pending = kind == "org_pat_requests"
        records = []
        for row in rows:
            require_id(row.get("id"))
            if not pending:
                require_id(row.get("token_id"))
            record = project_pat(row, REQUEST_FIELDS if pending else PAT_FIELDS)
            records.append(record)
            resource = ("personal-access-token-requests" if pending
                        else "personal-access-tokens")
            output["tasks"].append(task(
                enterprise, org,
                "org_pat_request_repositories" if pending else "org_fgpat_repositories",
                f"/orgs/{org}/{resource}/{record['id']}/repositories",
                context={"credential": record}, priority=55))
            if pending:
                output["contexts"].append(_context(current, "pat_request", record["id"], record))
        if not pending:
            output["reports"].append(_report(current, {"fine_grained_pat": {
                "source": "organization_fine_grained_pat", "fine_grained_pats": records}}))
    elif kind in {"org_fgpat_repositories", "org_pat_request_repositories"}:
        repos = [repository_metadata(row, org) for row in rows]
        record = deepcopy(context["credential"])
        if kind == "org_fgpat_repositories":
            record["repositories"] = repos
            output["reports"].append(_report(current, {"fine_grained_pat": {
                "source": "organization_fine_grained_pat_repositories",
                "fine_grained_pats": [record]}}))
        else:
            record["requested_repositories"] = repos
            output["contexts"].append(_context(current, "pat_request_repositories",
                                               record["id"], record))
    elif kind == "org_repositories":
        for row in rows:
            repo = repository_metadata(row, org)
            output["contexts"].append(_context(current, "collector_accessible_repository",
                                               repo["id"], repo))
            base = f"/repos/{org}/{repo['name']}"
            for task_kind in repository_read_kinds(options):
                if task_kind == "repo_fork_policy" and repo.get("visibility") == "public":
                    continue
                suffix, paginated = REPOSITORY_READS[task_kind]
                if task_kind == "repo_actions_runs":
                    suffix += "?" + urlencode({"created": options["run_window"]})
                output["tasks"].append(task(enterprise, org, task_kind, base + suffix,
                                            paginated=paginated, context={"repository": repo},
                                            collection_key={"repo_actions_secrets": "secrets", "repo_environments": "environments"}.get(task_kind),
                                            priority=60))
    elif kind == "repo_deploy_keys":
        records = [deploy_key_metadata(row, context["repository"]) for row in rows]
        output["reports"].append(_report(current, {"deploy_key": {
            "source": "repository_deploy_keys", "deploy_keys": records}}))
    elif kind == "org_installations":
        for row in rows:
            require_id(row.get("id"))
        records = [project_installation(row, "installations", org) for row in rows]
        output["reports"].append(_report(current, {"github_app_installation_token": {
            "source": "organization_github_app_installations", "installations": records}}))
    elif kind == "enterprise_org_installations":
        records = []
        for row in rows:
            install_id = require_id(row.get("id"))
            record = pick(row, ENTERPRISE_INSTALLATION_FIELDS)
            record["account"] = {"login": org, "type": "Organization"}
            record["installation_id"] = install_id
            records.append(record)
            output["contexts"].append(_context(current, "enterprise_org_installation",
                                               install_id, record))
            output["tasks"].append(task(
                enterprise, org, "enterprise_installation_repositories",
                f"/enterprises/{slug(enterprise)}/apps/organizations/{org}"
                f"/installations/{install_id}/repositories", auth="enterprise",
                context={"installation_id": install_id, "installation": record}, priority=55))
        output["reports"].append(_report(current, {"github_app_installation_token": {
            "source": "enterprise_organization_installations", "installations": records}}))
    elif kind in {"enterprise_org_repositories", "enterprise_installation_repositories"}:
        repositories = []
        for row in rows:
            repo = repository_metadata(row, org, shallow=True)
            repositories.append(repo)
            if kind == "enterprise_org_repositories":
                # This says which repositories could be granted, not that the
                # collector or any listed installation has access to them.
                output["contexts"].append(_context(current, "enterprise_org_repository",
                                                   repo["id"], repo))
            else:
                output["contexts"].append(_context(
                    current, "installation_repository",
                    f"{context['installation_id']}:{repo['id']}",
                    {"installation_id": context["installation_id"], "repository": repo}))
        if kind == "enterprise_installation_repositories":
            installation = deepcopy(context["installation"])
            installation["repositories"] = repositories
            output["reports"].append(_report(current, {"github_app_installation_token": {
                "source": "enterprise_organization_installation_repositories",
                "installations": [installation]}}))
    else:
        raise EndpointError("unknown_supplemental_task_kind")
    return output


def _runs(data):
    runs = data.get("workflow_runs") if isinstance(data, dict) else None
    if not isinstance(runs, list) or not all(isinstance(row, dict) for row in runs):
        raise EndpointError("unexpected_supplemental_response_shape")
    return runs


def _jobs(data):
    jobs = data.get("jobs") if isinstance(data, dict) else None
    if not isinstance(jobs, list) or not all(isinstance(row, dict) for row in jobs):
        raise EndpointError("unexpected_supplemental_response_shape")
    return jobs


def handle_enterprise_page(current, data, headers, *, enterprise, window, include_audit,
                           sources=(), include_actions=False, server=False):
    """The Enterprise engine's own page kinds: inventory, organizations, audit."""
    kind = current["kind"]
    output = {"inventory_items": [], "reports": [], "contexts": [], "tasks": [], "warnings": [],
              "generated_at": None}
    if not isinstance(data, list) or not all(isinstance(row, dict) for row in data):
        raise EndpointError("invalid_page_response")
    if kind == "inventory":
        validate_inventory_page(data)
        output["warnings"], output["generated_at"] = inventory_flags(headers)
        output["inventory_items"] = data
    elif kind == "organizations":
        organizations = []
        for row in data:
            org = slug(row.get("login"))
            require_id(row.get("id"))
            organizations.append({"id": row["id"], "login": org})
            output["tasks"].extend(seed_org_tasks(enterprise, org, sources=sources,
                                                  include_actions=include_actions, server=server))
            if include_audit:
                output["tasks"].append(task(enterprise, org, "org_audit",
                                            audit_path(org, window), auth="org", priority=90))
        output["contexts"] = [{"kind": "enterprise_organizations", "scope": enterprise,
                               "org": "", "external_id": enterprise,
                               "source_endpoint": current["path"], "metadata": organizations}]
    elif kind in ("audit", "org_audit", "git_audit"):
        validate_audit_page(data, enterprise, current.get("org"))
        output["contexts"] = [{"kind": "audit_events", "scope": current.get("org") or enterprise,
                               "org": current.get("org") or "", "external_id": current["path"],
                               "source_endpoint": current["path"].split("?", 1)[0],
                               "metadata": data}]
    else:
        raise EndpointError("unknown_supplemental_task_kind")
    return output
