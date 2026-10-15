"""Relationship evidence stays classed: observed, provider-attributed, possible."""

from __future__ import annotations

import unittest
from datetime import UTC, datetime

from cremore_gcp_provider.metadata.relations import ACCESS_METHOD, RelationshipCollector
from cremore_gcp_provider.metadata.transport import ApiError, Budget

from .fake import API_KEY_NAME, API_KEY_UID, EMAIL, KEY_ID, PROJECT, SECRET, FakeTransport

END = datetime(2026, 9, 21, 12, 0, tzinfo=UTC)
KEY_NAME = f"projects/{PROJECT}/serviceAccounts/{EMAIL}/keys/{KEY_ID}"
LOG_KEY = f"//iam.googleapis.com/projects/{PROJECT}/serviceAccounts/{EMAIL}/keys/{KEY_ID}"
LOGS = "https://logging.googleapis.com/v2/entries:list"
METRICS = f"https://monitoring.googleapis.com/v3/projects/{PROJECT}/timeSeries"
IAM = f"https://cloudresourcemanager.googleapis.com/v1/projects/{PROJECT}:getIamPolicy"


def index(**overrides):
    base = {
        "principals": {EMAIL: f"projects/{PROJECT}/serviceAccounts/{EMAIL}"},
        "keys": {(EMAIL, KEY_ID): KEY_NAME},
        "api_keys": {API_KEY_UID.lower(): API_KEY_NAME},
        "missing_api_uid": 0,
        "secrets": {"deploy-token": SECRET},
        "project_aliases": {PROJECT},
    }
    return {**base, **overrides}


def collector(responses, **overrides):
    return RelationshipCollector(PROJECT, index(**overrides), FakeTransport(responses), end=END)


def entry(*, resource=SECRET + "/versions/2", email=EMAIL, key=LOG_KEY, status=None,
          timestamp="2026-09-21T11:00:00Z", method=ACCESS_METHOD,
          service="secretmanager.googleapis.com", insert="e1"):
    auth = {"principalEmail": email}
    if key is not None:
        auth["serviceAccountKeyName"] = key
    return {"logName": f"projects/{PROJECT}/logs/cloudaudit.googleapis.com%2Fdata_access",
            "insertId": insert, "timestamp": timestamp,
            "protoPayload": {"serviceName": service, "methodName": method,
                             "resourceName": resource, "status": status,
                             "authenticationInfo": auth}}


def drain(pages):
    edges, last = [], None
    for page in pages:
        edges.extend(page.rows)
        last = page
    return edges, last


class SecretAccessTests(unittest.TestCase):
    def test_audit_stream_identity_is_exact_and_normalizes_verified_project_aliases(self):
        api = collector({}, project_aliases={PROJECT, "123456789012"})
        for encoded in ("%2F", "%2f", "/"):
            name = f"projects/123456789012/logs/cloudaudit.googleapis.com{encoded}data_access"
            self.assertEqual(api.audit_log_name(name),
                             "projects/123456789012/logs/cloudaudit.googleapis.com%2Fdata_access")
        query = api.base_filter()
        self.assertNotIn('logName:', query)
        self.assertIn(f'logName="projects/{PROJECT}/logs/cloudaudit.googleapis.com%2Fdata_access"', query)
        for name in ("projects/other/logs/cloudaudit.googleapis.com%2Fdata_access",
                     f"projects/{PROJECT}/logs/application",
                     f"projects/{PROJECT}/logs/cloudaudit.googleapis.com%252Fdata_access",
                     f"projects/{PROJECT}/logs/cloudaudit.googleapis.com%2Fdata_access/extra"):
            row = {**entry(), "logName": name}
            scoped = collector({LOGS: {"entries": [row]}})
            self.assertEqual(drain(scoped.secret_access())[0], [])
            self.assertEqual(scoped.issues.get("invalid_log_evidence"), 1)

    def test_unlisted_principal_classification_requires_the_exact_service_account_domain(self):
        api = collector({})
        for email in ("worker@gserviceaccount.com", "worker@demo.iam.gserviceaccount.com"):
            self.assertEqual(api.principal_id(email), f"gcp_principal:serviceAccount:{email}")
        for email in ("worker@notgserviceaccount.com", "worker@gserviceaccount.com.example.org"):
            self.assertEqual(api.principal_id(email), f"gcp_principal:user:{email}")
        self.assertEqual(api.principal_id(EMAIL), index()["principals"][EMAIL])

    def test_one_entry_attributes_the_principal_the_key_the_secret_and_the_version(self):
        edges, page = drain(collector({LOGS: {"entries": [entry()]}}).secret_access())
        self.assertEqual(page.status, "complete")
        self.assertEqual([edge["relation"] for edge in edges], [
            "secret_access_observed", "secret_version_access_observed",
            "service_account_key_secret_access_observed",
            "service_account_key_version_access_observed"])
        self.assertTrue(all(edge["evidence_class"] == "observed_access" for edge in edges))
        self.assertTrue(all(edge["collection_scope"]["window_end"] for edge in edges))

    def test_a_failed_attempt_is_counted_and_never_becomes_observed_access(self):
        api = collector({LOGS: {"entries": [entry(status={"code": 7})]}})
        edges, _ = drain(api.secret_access())
        self.assertEqual(edges, [])
        self.assertEqual(api.issues, {"failed_secret_access_attempt": 1})

    def test_an_unknown_principal_or_secret_leaves_the_entry_unattributed(self):
        api = collector({LOGS: {"entries": [entry(resource="projects/other/secrets/x/versions/1")]}})
        self.assertEqual(drain(api.secret_access())[0], [])
        self.assertEqual(api.issues, {"unmatched_secret_version": 1})

        api = collector({LOGS: {"entries": [entry(email="nobody@example.com", key=None)]}})
        edges, _ = drain(api.secret_access())
        # A principal outside the inventory is still named, never dropped.
        self.assertEqual(edges[0]["source_id"], "gcp_principal:user:nobody@example.com")

    def test_a_key_name_for_another_principal_or_project_is_not_attributed(self):
        other = f"//iam.googleapis.com/projects/{PROJECT}/serviceAccounts/other@x.test/keys/{KEY_ID}"
        api = collector({LOGS: {"entries": [entry(key=other)]}})
        edges, _ = drain(api.secret_access())
        self.assertEqual(len(edges), 2)
        self.assertEqual(api.issues, {"unmatched_service_account_key_name": 1})

    def test_an_entry_outside_the_window_is_refused(self):
        api = collector({LOGS: {"entries": [entry(timestamp="2026-09-01T00:00:00Z")]}})
        self.assertEqual(drain(api.secret_access())[0], [])
        self.assertIn("log_outside_window", api.issues)

    def test_the_audit_payload_body_never_leaves_the_transport(self):
        row = entry()
        row["protoPayload"]["request"] = {"name": "projects/p/secrets/s/versions/1"}
        row["protoPayload"]["response"] = {"payload": {"data": "c2VjcmV0"}}
        api = collector({LOGS: {"entries": [row]}})
        edges, _ = drain(api.secret_access())
        self.assertNotIn("c2VjcmV0", repr(edges))
        self.assertNotIn("response", repr(edges))


class ActivityTests(unittest.TestCase):
    def test_activity_is_attributed_to_the_account_and_its_key(self):
        row = entry(method="storage.objects.get", service="storage.googleapis.com",
                    resource="projects/_/buckets/build-artifacts")
        edges, _ = drain(collector({LOGS: {"entries": [row]}}).service_account_activity())
        self.assertEqual([edge["relation"] for edge in edges],
                         ["service_account_activity_observed",
                          "service_account_key_activity_observed"])
        self.assertEqual(edges[0]["method_name"], "storage.objects.get")

    def test_secret_access_is_not_counted_twice_as_generic_activity(self):
        edges, _ = drain(collector({LOGS: {"entries": [entry()]}}).service_account_activity())
        self.assertEqual(edges, [])

    def test_an_action_on_a_key_is_the_account_activity_and_never_the_keys_use(self):
        from cremore_gcp_provider.metadata.normalization import relation

        from .fake import spec

        for service, method, resource in (
                ("apikeys.googleapis.com", "google.api.apikeys.v2.ApiKeys.UpdateKey", API_KEY_NAME),
                ("apikeys.googleapis.com", "google.api.apikeys.v2.ApiKeys.GetKeyString", API_KEY_NAME),
                ("iam.googleapis.com", "google.iam.admin.v1.DisableServiceAccountKey", KEY_NAME)):
            with self.subTest(method=method):
                row = entry(method=method, service=service, resource=resource)
                api = collector({LOGS: {"entries": [row]}})
                edges, _ = drain(api.service_account_activity())
                self.assertEqual({edge["target_id"] for edge in edges}, {f"gcp_api:{service}"})
                self.assertEqual(api.issues, {})
                connection = spec(capabilities=["inventory", "relations"])
                records = [relation(connection, connection.scopes[0], edge) for edge in edges]
                self.assertTrue(all(record.target.kind == "resource" for record in records))
                # The key that authenticated the call is still that key's own observed use.
                self.assertIn(f"serviceAccountKey:{EMAIL}:{KEY_ID}",
                              {record.subject.object_id for record in records})


class MetricTests(unittest.TestCase):
    def series(self, points, **labels):
        return {METRICS: {"timeSeries": [{
            "resource": {"type": "consumed_api",
                         "labels": {"credential_id": f"apikey:{API_KEY_UID}",
                                    "service": "maps.googleapis.com", "project_id": PROJECT,
                                    **labels}},
            "metric": {"type": "serviceruntime.googleapis.com/api/request_count"},
            "points": points}]}}

    def point(self, count, start="2026-09-21T10:00:00Z", end="2026-09-21T11:00:00Z"):
        return {"interval": {"startTime": start, "endTime": end},
                "value": {"int64Value": str(count)}}

    def test_requests_are_summed_per_service_with_the_observed_window(self):
        api = collector(self.series([self.point(40), self.point(
            2, "2026-09-21T11:00:00Z", "2026-09-21T11:30:00Z")]))
        edges, _ = drain(api.api_key_metrics(API_KEY_UID.lower(), API_KEY_NAME))
        self.assertEqual(len(edges), 1)
        self.assertEqual(edges[0]["request_count"], 42)
        self.assertEqual(edges[0]["caller_identity"], "unknown")
        self.assertEqual(edges[0]["last_observed_at"], "2026-09-21T11:30:00Z")

    def test_a_zero_count_produces_no_edge_and_is_not_called_unused(self):
        api = collector(self.series([self.point(0)]))
        edges, _ = drain(api.api_key_metrics(API_KEY_UID.lower(), API_KEY_NAME))
        self.assertEqual(edges, [])
        self.assertEqual(api.issues, {})

    def test_a_series_for_another_key_or_project_is_refused(self):
        api = collector(self.series([self.point(5)], credential_id="apikey:other"))
        self.assertEqual(drain(api.api_key_metrics(API_KEY_UID.lower(), API_KEY_NAME))[0], [])
        self.assertEqual(api.issues, {"unmatched_metric_series": 1})

    def test_a_point_outside_the_window_or_with_a_bad_count_is_refused(self):
        api = collector(self.series([self.point(5, "2026-01-01T00:00:00Z", "2026-01-01T01:00:00Z"),
                                     {"interval": {}, "value": {"int64Value": "x"}}]))
        self.assertEqual(drain(api.api_key_metrics(API_KEY_UID.lower(), API_KEY_NAME))[0], [])
        self.assertEqual(api.issues, {"invalid_metric_point": 2})

    def test_a_delta_point_that_began_before_the_window_is_counted(self):
        # 24 hours before END is the window start; Google selects points by end time in (start, end].
        api = collector(self.series([self.point(7, "2026-09-20T11:59:30Z", "2026-09-20T12:00:30Z")]))
        edges, _ = drain(api.api_key_metrics(API_KEY_UID.lower(), API_KEY_NAME))
        self.assertEqual(api.issues, {})
        self.assertEqual([edge["request_count"] for edge in edges], [7])
        self.assertEqual(edges[0]["first_observed_at"], "2026-09-20T11:59:30Z")
        ended = collector(self.series([self.point(7, "2026-09-20T11:59:00Z", "2026-09-20T12:00:00Z")]))
        self.assertEqual(drain(ended.api_key_metrics(API_KEY_UID.lower(), API_KEY_NAME))[0], [])
        self.assertEqual(ended.issues, {"invalid_metric_point": 1})


class PolicyTests(unittest.TestCase):
    def test_policy_expansion_checks_the_remaining_budget_before_allocating_edges(self):
        from unittest.mock import patch

        api = self.policy([{"role": "roles/secretmanager.secretAccessor",
                            "members": ["user:first@example.test", "user:second@example.test"]}])
        api.secrets["other"] = SECRET + "-other"
        api.max_edges = 2
        with patch.object(api, "_edge", wraps=api._edge) as edge:
            with self.assertRaisesRegex(Budget, "RECORD_BUDGET_EXCEEDED"):
                api.project_policy()
            self.assertEqual(edge.call_count, 2)

    def policy(self, bindings, extra=None):
        return collector({IAM: {"bindings": bindings}, **(extra or {})})

    def test_only_a_role_that_can_read_a_version_becomes_possible_access(self):
        api = self.policy([
            {"role": "roles/secretmanager.secretAccessor", "members": [f"serviceAccount:{EMAIL}"]},
            {"role": "roles/viewer", "members": [f"serviceAccount:{EMAIL}"]},
        ])
        edges = api.project_policy()
        self.assertEqual(len(edges), 1)
        self.assertEqual(edges[0]["evidence_class"], "policy_possible")
        self.assertEqual(edges[0]["effective_access"], "not_evaluated")
        self.assertIsNone(edges[0]["collection_scope"]["window_start"])

    def test_a_custom_role_is_resolved_by_its_permissions_and_cached(self):
        role = f"projects/{PROJECT}/roles/reader"
        api = self.policy([{"role": role, "members": [f"serviceAccount:{EMAIL}"]}],
                          {f"https://iam.googleapis.com/v1/{role}": {
                              "includedPermissions": ["secretmanager.versions.access"]}})
        self.assertEqual(len(api.project_policy()), 1)
        self.assertIs(api.role_cache[role], True)

    def test_an_unresolvable_role_is_an_issue_and_grants_nothing(self):
        role = f"projects/{PROJECT}/roles/mystery"
        api = self.policy([{"role": role, "members": [f"serviceAccount:{EMAIL}"]}])
        self.assertEqual(api.project_policy(), [])
        self.assertEqual(api.issues, {"unresolved_role": 1})

    def test_a_conditional_or_indirect_member_is_unconfirmed_not_possible(self):
        api = self.policy([{"role": "roles/owner", "members": [f"serviceAccount:{EMAIL}"],
                            "condition": {"expression": "true"}},
                           {"role": "roles/owner", "members": ["group:team@example.com"]}])
        classes = {edge["source_id"]: edge["evidence_class"] for edge in api.project_policy()}
        self.assertEqual(classes[f"projects/{PROJECT}/serviceAccounts/{EMAIL}"], "unconfirmed")
        self.assertEqual(classes["iam_member:group:team@example.com"], "unconfirmed")

    def test_a_refused_policy_read_raises_rather_than_reporting_no_access(self):
        api = collector({})
        with self.assertRaises(ApiError):
            api.project_policy()


if __name__ == "__main__":
    unittest.main()
