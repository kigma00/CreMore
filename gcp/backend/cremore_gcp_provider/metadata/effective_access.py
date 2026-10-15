"""What a service account's key can do on its project, as Google's Policy Troubleshooter evaluates it.

``iam:troubleshoot`` (v3) answers for one principal, resource and permission with the allow policies on the
resource and every ancestor (folder, organization), the groups it can see, conditional bindings and deny
policies. A policy or group membership the connection cannot view makes the answer UNKNOWN_INFO, and a
condition that depends on the request makes it UNKNOWN_CONDITIONAL: both stay unknown, never a denial. v3 does
not evaluate principal access boundary policies (only v3beta explains them), so a boundary can still narrow
what CAN_ACCESS shows.

A curated set of high-impact permissions is asked on the project itself, so a grant made only on one bucket,
secret or key ring is not seen; resource-level policies stay outside this answer. The evaluation runs with the
connection's own identity (it needs the Security Reviewer and Deny Reviewer roles to see every layer), never
with a discovered key.
https://cloud.google.com/policy-intelligence/docs/troubleshoot-access
"""

from __future__ import annotations

from cremore_gcp.transport import ApiError

from cremore.coverage.facts import FactWriter
from cremore.coverage.metadata_models import MetadataPermission

URL = "https://policytroubleshooter.googleapis.com/v3/iam:troubleshoot"
PERMISSIONS = (
    "iam.serviceAccountKeys.create", "iam.serviceAccounts.actAs", "iam.serviceAccounts.getAccessToken",
    "resourcemanager.projects.setIamPolicy", "secretmanager.versions.access",
    "cloudkms.cryptoKeyVersions.useToDecrypt", "storage.objects.delete", "cloudfunctions.functions.update",
    "run.services.update", "compute.instances.create", "storage.objects.get",
)
# Service accounts asked per collection: each costs one request per permission.
MAX_PRINCIPALS = 20
_OVERALL = {"CAN_ACCESS": "can_access", "CANNOT_ACCESS": "cannot_access",
            "UNKNOWN_INFO": "unknown_info", "UNKNOWN_CONDITIONAL": "unknown_conditional"}
_DENY = {"DENY_ACCESS_STATE_DENIED": "denied", "DENY_ACCESS_STATE_NOT_DENIED": "not_denied",
         "DENY_ACCESS_STATE_UNKNOWN_CONDITIONAL": "unknown_conditional",
         "DENY_ACCESS_STATE_UNKNOWN_INFO": "unknown_info"}
_EFFECT = {"can_access": "ALLOW", "cannot_access": "DENY"}


def evaluate(transport, project: str, email: str) -> tuple[list[dict], dict[str, int]]:
    """One answer per curated permission for ``email`` on ``projects/<project>``, and the error codes met. A
    failed request leaves that permission not evaluated; a throttled one is raised so the run waits."""
    from cremore_gcp_provider.metadata.transport import DEFERRED

    answers, errors = [], {}
    for permission in PERMISSIONS:
        body = {"accessTuple": {"principal": email, "permission": permission,
                                "fullResourceName": f"//cloudresourcemanager.googleapis.com/projects/{project}"}}
        try:
            response = transport.post_readonly(URL, body)
            if response.get("overallAccessState") not in _OVERALL:
                raise ApiError("invalid_response")
        except ApiError as exc:
            if exc.code in DEFERRED:
                raise
            errors[exc.code] = errors.get(exc.code, 0) + 1
            answers.append({"permission": permission, "state": "not_evaluated", "error": exc.code})
            if exc.code == "api_disabled":
                # Off for one permission is off for all: the rest are not asked.
                answers += [{"permission": name, "state": "not_evaluated", "error": exc.code}
                            for name in PERMISSIONS[len(answers):]]
                break
            continue
        deny = response.get("denyPolicyExplanation")
        answers.append({
            "permission": permission, "state": _OVERALL[response["overallAccessState"]],
            "deny": _DENY.get(deny.get("denyAccessState"), "not_reported") if isinstance(deny, dict) else "not_reported",
        })
    return answers, errors


def permissions(project: str, answers: list[dict]) -> list[MetadataPermission]:
    """The answers as the key's permissions: CAN_ACCESS is ALLOW, CANNOT_ACCESS is DENY, anything else UNKNOWN,
    each with what the troubleshooter evaluated (nothing, for a failed call)."""
    out = []
    for answer in answers:
        if answer.get("error"):
            facts = dict.fromkeys(("effective_access", "inherited_policies", "membership_resolution",
                                   "deny_policies", "condition_evaluation"), "not_evaluated")
            facts["error_code"] = answer["error"]
        else:
            facts = {"effective_access": answer["state"], "inherited_policies": "evaluated",
                     "membership_resolution": "evaluated", "deny_policies": answer.get("deny", "not_reported"),
                     "condition_evaluation": "unknown_conditional" if answer["state"] == "unknown_conditional"
                     else "evaluated"}
        facts["principal_access_boundaries"] = "not_evaluated"
        out.append(MetadataPermission(
            kind="permission", name=answer["permission"], resource_kind="project", resource_id=f"projects/{project}",
            effect=_EFFECT.get(answer["state"], "UNKNOWN"), conditions=FactWriter().facts(facts)))
    return out
