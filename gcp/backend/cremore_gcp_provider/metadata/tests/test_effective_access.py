"""What a user-managed key's account can do on its project, as Policy Troubleshooter answers. Scripted only."""

from __future__ import annotations

import unittest
from unittest import mock

from cremore.coverage.facts import unpack_facts
from cremore_gcp_provider.metadata import adapter, effective_access
from cremore_gcp_provider.metadata.transport import ApiError

from .fake import EMAIL, OTHER_EMAIL, PROJECT, FakeTransport, drain, inventory_responses, spec
from .test_adapter import NOW

RESOURCE = f"//cloudresourcemanager.googleapis.com/projects/{PROJECT}"
CONNECTION = spec(capabilities=["inventory", "relations"], options={"sources": ["effective_access"]})


class Troubleshooter(FakeTransport):
    """Answers iam:troubleshoot by principal and permission (CANNOT_ACCESS unless ``answers`` says otherwise).
    ``refuse`` fails a permission as the real transport words a 403, ``blank`` answers it without a state,
    ``throttle`` raises a rate limit once for a (principal, permission) and ``disabled`` answers SERVICE_DISABLED."""

    def __init__(self, answers=None, *, refuse=(), blank=(), throttle=(), disabled=False, responses=None):
        super().__init__(responses or inventory_responses(secrets=False))
        self.answers, self.refuse, self.blank = dict(answers or {}), set(refuse), set(blank)
        self.throttle, self.disabled, self.asked = set(throttle), disabled, []

    def post_readonly(self, url, body, params=None):
        if url != effective_access.URL:
            return super().post_readonly(url, body, params)
        asked = body["accessTuple"]
        self.asked.append((asked["principal"], asked["permission"], asked["fullResourceName"]))
        if (asked["principal"], asked["permission"]) in self.throttle:
            self.throttle.discard((asked["principal"], asked["permission"]))
            raise ApiError("rate_limited")
        if self.disabled:
            raise ApiError("api_disabled")
        if asked["permission"] in self.refuse:
            raise ApiError("permission_denied_or_api_disabled")
        if asked["permission"] in self.blank:
            return {}
        state = self.answers.get((asked["principal"], asked["permission"]), "CANNOT_ACCESS")
        return {"overallAccessState": state,
                "denyPolicyExplanation": {"denyAccessState": "DENY_ACCESS_STATE_DENIED" if state == "CANNOT_ACCESS"
                                          and asked["permission"] == "storage.objects.delete" else "DENY_ACCESS_STATE_NOT_DENIED"}}


def collected(transport, sources=("effective_access",)):
    connection = spec(capabilities=["inventory", "relations"], options={"sources": list(sources)})
    records, final = drain(adapter.collect_pages(connection, secrets={}, checkpoint={}, check=lambda: None,
                                                 transport=transport, now=NOW))
    return [record.model_dump() for record in records], final


def keys(records):
    return {row["identity"]["object_id"]: row for row in records
            if row["record_type"] == "entity_observation" and row["identity"]["object_id"].startswith("serviceAccountKey:")}


def access(row):
    return {item["name"]: (item["effect"], unpack_facts(item["conditions"])) for item in row["permissions"]}


def key_report(records):
    return next(row for row in records if row["record_type"] == "operation_report"
                and row["provenance"]["operation"] == "gcp.service_account_keys")


def managed_key(records, email=EMAIL):
    return next(row for oid, row in keys(records).items() if oid.startswith(f"serviceAccountKey:{email}:0123"))


def counts(fact):
    return {row["code"]: row["count"] for row in fact or []}


class EffectiveAccessTests(unittest.TestCase):
    def test_each_user_managed_key_carries_what_its_account_may_do_on_the_project(self):
        transport = Troubleshooter({(EMAIL, "storage.objects.get"): "CAN_ACCESS",
                                    (EMAIL, "secretmanager.versions.access"): "UNKNOWN_CONDITIONAL",
                                    (EMAIL, "iam.serviceAccountKeys.create"): "UNKNOWN_INFO"})
        records, final = collected(transport)
        result = access(managed_key(records))
        self.assertEqual(len(result), len(effective_access.PERMISSIONS))
        self.assertEqual(result["storage.objects.get"][0], "ALLOW")
        self.assertEqual(result["storage.objects.get"][1]["effective_access"], "can_access")
        self.assertEqual(result["storage.objects.get"][1]["inherited_policies"], "evaluated")
        # v3 does not evaluate principal access boundaries.
        self.assertEqual(result["storage.objects.get"][1]["principal_access_boundaries"], "not_evaluated")
        # A condition that depends on the request, or a policy the identity cannot see, stays unknown: never a denial.
        self.assertEqual(result["secretmanager.versions.access"][0], "UNKNOWN")
        self.assertEqual(result["secretmanager.versions.access"][1]["condition_evaluation"], "unknown_conditional")
        self.assertEqual(result["iam.serviceAccountKeys.create"][0], "UNKNOWN")
        self.assertEqual(result["storage.objects.delete"], ("DENY", result["storage.objects.delete"][1]))
        self.assertEqual(result["storage.objects.delete"][1]["deny_policies"], "denied")
        self.assertTrue(all(item["resource_id"] == f"projects/{PROJECT}" for item in managed_key(records)["permissions"]))
        # A Google-managed key is never downloaded, so it carries nothing.
        system = next(row for oid, row in keys(records).items() if oid.endswith(":system"))
        self.assertEqual(system["permissions"], [])
        # Each account with a user-managed key is asked once per permission, on the project.
        self.assertEqual({principal for principal, _p, _r in transport.asked}, {EMAIL, OTHER_EMAIL})
        self.assertEqual(len(transport.asked), 2 * len(effective_access.PERMISSIONS))
        self.assertEqual({resource for _a, _p, resource in transport.asked}, {RESOURCE})
        report = unpack_facts(key_report(records)["facts"])
        self.assertIn("effective access answered for 2 accounts", report["selection"])
        # How Google answered, counted: an all-unknown collection is visible in its report.
        self.assertEqual(counts(report["effective_access"]), {"can_access": 1, "cannot_access": 19,
                                                              "unknown_conditional": 1, "unknown_info": 1})
        self.assertIsNotNone(final)

    def test_a_refused_call_is_not_evaluated_and_never_degrades_the_key_listing(self):
        baseline = key_report(collected(Troubleshooter())[0])
        transport = Troubleshooter(refuse={"storage.objects.get"})
        records, _final = collected(transport)
        effect, facts = access(managed_key(records))["storage.objects.get"]
        self.assertEqual((effect, facts["effective_access"], facts["inherited_policies"], facts["error_code"]),
                         ("UNKNOWN", "not_evaluated", "not_evaluated", "permission_denied_or_api_disabled"))
        report = key_report(records)
        # The listing's own status and reasons are what they were (the fixture's malformed key name only).
        self.assertEqual((report["status"], report["reasons"]), (baseline["status"], baseline["reasons"]))
        error_counts = counts(unpack_facts(report["facts"])["error_counts"])
        self.assertEqual(error_counts["troubleshooter_permission_denied_or_api_disabled"], 2)

    def test_an_answer_without_an_access_state_is_not_evaluated(self):
        records, _final = collected(Troubleshooter(blank={"storage.objects.get"}))
        effect, facts = access(managed_key(records))["storage.objects.get"]
        self.assertEqual((effect, facts["effective_access"], facts["error_code"]), ("UNKNOWN", "not_evaluated", "invalid_response"))

    def test_without_the_option_nothing_is_asked(self):
        transport = Troubleshooter()
        records, _final = collected(transport, sources=("service_account_iam",))
        self.assertEqual(transport.asked, [])
        self.assertTrue(all(row["permissions"] == [] for row in keys(records).values()))

    def test_accounts_past_the_limit_stay_unevaluated_and_are_counted(self):
        transport = Troubleshooter()
        with mock.patch.object(effective_access, "MAX_PRINCIPALS", 1):
            records, _final = collected(transport)
        self.assertEqual({principal for principal, _p, _r in transport.asked}, {min(EMAIL, OTHER_EMAIL)})
        self.assertIn("1 not evaluated (limit 1)", unpack_facts(key_report(records)["facts"])["selection"])

    def test_an_api_that_is_off_is_asked_once_and_leaves_every_answer_unevaluated(self):
        transport = Troubleshooter(disabled=True)
        records, _final = collected(transport)
        # Accounts are asked in sorted order: EMAIL first, OTHER_EMAIL never.
        self.assertEqual([principal for principal, _p, _r in transport.asked], [EMAIL])
        managed = managed_key(records)
        self.assertEqual({(effect, facts["effective_access"], facts["error_code"]) for effect, facts in access(managed).values()},
                         {("UNKNOWN", "not_evaluated", "api_disabled")})
        self.assertEqual(len(managed["permissions"]), len(effective_access.PERMISSIONS))
        report = unpack_facts(key_report(records)["facts"])
        self.assertIn("answered for 0 accounts with user-managed keys, 2 not evaluated (limit 20; stopped after api_disabled)",
                      report["selection"])

    def test_a_caller_refused_for_every_permission_stops_after_one_account(self):
        transport = Troubleshooter(refuse=set(effective_access.PERMISSIONS))
        records, _final = collected(transport)
        self.assertEqual({principal for principal, _p, _r in transport.asked}, {EMAIL})
        self.assertIn("stopped after permission_denied_or_api_disabled",
                      unpack_facts(key_report(records)["facts"])["selection"])

    def test_an_account_without_an_answer_stops_the_asking_whatever_the_code(self):
        # Every call failing (a blocked host, an unreadable answer) costs 11 requests an account: one account is enough.
        transport = Troubleshooter(blank=set(effective_access.PERMISSIONS))
        records, _final = collected(transport)
        self.assertEqual(len(transport.asked), len(effective_access.PERMISSIONS))
        self.assertIn("answered for 0 accounts with user-managed keys, 2 not evaluated (limit 20; stopped after invalid_response)",
                      unpack_facts(key_report(records)["facts"])["selection"])

    def test_the_limit_counts_every_account_asked(self):
        transport = Troubleshooter(blank={"storage.objects.get"})
        with mock.patch.object(effective_access, "MAX_PRINCIPALS", 1):
            collected(transport)
        self.assertEqual({principal for principal, _p, _r in transport.asked}, {EMAIL})

    def test_a_throttled_evaluation_resumes_without_counting_an_account_twice(self):
        responses = inventory_responses(secrets=False)
        for email in (EMAIL, OTHER_EMAIL):  # without the fixture's malformed key name, the listing is complete
            listing = responses[f"https://iam.googleapis.com/v1/projects/{PROJECT}/serviceAccounts/{email}/keys"]
            listing["keys"] = listing["keys"][:2]
        throttled = Troubleshooter(throttle={(OTHER_EMAIL, "storage.objects.get")}, responses=responses)
        first, waiting = drain(adapter.collect_pages(CONNECTION, secrets={}, checkpoint={}, check=lambda: None,
                                                     transport=throttled, now=NOW))
        self.assertEqual(waiting.status, "WAITING")
        records, final = drain(adapter.collect_pages(
            CONNECTION, secrets={}, checkpoint=waiting.checkpoint, check=lambda: None, now=NOW,
            transport=Troubleshooter(responses=responses), read_records=lambda: [row.model_dump() for row in first]))
        report = key_report([row.model_dump() for row in records])
        facts = unpack_facts(report["facts"])
        self.assertEqual((report["status"], facts["accounts_checked"], facts["accounts_seen"]), ("COMPLETE", 2, 2))
        self.assertIn("answered for 2 accounts", facts["selection"])
        self.assertEqual(sum(counts(facts["effective_access"]).values()), 2 * len(effective_access.PERMISSIONS))
        self.assertIsNotNone(final)

    def test_the_source_needs_the_relations_capability(self):
        adapter.validate_spec(spec(capabilities=["inventory", "relations"], options={"sources": ["effective_access"]}))
        with self.assertRaises(ValueError):
            adapter.validate_spec(spec(capabilities=["inventory"], options={"sources": ["effective_access"]}))


if __name__ == "__main__":
    unittest.main()
