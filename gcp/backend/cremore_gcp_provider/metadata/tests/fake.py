"""A scripted Google API surface. No network, no credentials, no real project."""

from __future__ import annotations

from copy import deepcopy

from cremore.coverage.metadata_models import MetadataConnectionSpec
from cremore_gcp_provider.metadata.transport import ApiError, approved

PROJECT = "cremore-demo-project"
EMAIL = f"collector@{PROJECT}.iam.gserviceaccount.com"
OTHER_EMAIL = f"runner@{PROJECT}.iam.gserviceaccount.com"
KEY_ID = "0123456789abcdef0123456789abcdef01234567"
API_KEY_UID = "1a2b3c4d-5e6f-4a1b-8c2d-3e4f5a6b7c8d"
API_KEY_NAME = "projects/419699000000/locations/global/keys/6b1cf0a4-2d00-4c6e-9f7a-8c0000000001"
SECRET = f"projects/{PROJECT}/secrets/deploy-token"
REGIONAL_SECRET = f"projects/{PROJECT}/locations/europe-west4/secrets/regional-token"


class FakeTransport:
    """Answers only the URLs a test scripted; anything else is a 404."""

    def __init__(self, responses=None, *, failures=None, check=None):
        self.responses = dict(responses or {})
        self.failures = dict(failures or {})
        self.calls: list[tuple[str, str, dict | None]] = []
        self.check = check or (lambda: None)
        self.requests = 0

    def _answer(self, method, url, params, body=None):
        approved(url)
        self.check()
        self.requests += 1
        self.calls.append((method, url, dict(params or {})))
        key = (url, (params or {}).get("pageToken", ""))
        if key in self.failures:
            raise ApiError(self.failures.pop(key))
        if url in self.failures:
            raise ApiError(self.failures.pop(url))
        if key in self.responses:
            return deepcopy(self.responses[key])
        if url in self.responses:
            value = self.responses[url]
            if isinstance(value, list):
                if not value:
                    raise ApiError("http_404")
                return deepcopy(value.pop(0))
            return deepcopy(value)
        raise ApiError("http_404")

    def get(self, url, params=None):
        return self._answer("GET", url, params)

    def post_readonly(self, url, body, params=None):
        return self._answer("POST", url, params, body)


def service_state(state="ENABLED"):
    return {
        f"https://serviceusage.googleapis.com/v1/projects/{PROJECT}/services/{service}":
            {"state": state}
        for service in ("iam.googleapis.com", "apikeys.googleapis.com",
                        "secretmanager.googleapis.com")
    }


def inventory_responses(*, keys=True, secrets=True, locations=("europe-west4",)):
    data = service_state()
    data[f"https://cloudresourcemanager.googleapis.com/v3/projects/{PROJECT}"] = {
        "projectId": PROJECT, "name": "projects/419699000000"}
    data[f"https://iam.googleapis.com/v1/projects/{PROJECT}/serviceAccounts"] = {
        "accounts": [
            {"email": EMAIL, "disabled": False, "displayName": "collector", "uniqueId": "1001"},
            {"email": OTHER_EMAIL, "disabled": True, "uniqueId": "1002"},
            {"email": "not-an-email"},
        ]
    }
    for email in (EMAIL, OTHER_EMAIL):
        name = f"projects/{PROJECT}/serviceAccounts/{email}/keys"
        data[f"https://iam.googleapis.com/v1/{name}"] = {"keys": [
            {"name": f"projects/{PROJECT}/serviceAccounts/{email}/keys/{KEY_ID}",
             "keyType": "USER_MANAGED", "keyAlgorithm": "KEY_ALG_RSA_2048",
             "validAfterTime": "2026-01-01T00:00:00Z", "validBeforeTime": "2027-01-01T00:00:00Z",
             "disabled": False, "keyOrigin": "GOOGLE_PROVIDED"},
            {"name": f"projects/{PROJECT}/serviceAccounts/{email}/keys/system",
             "keyType": "SYSTEM_MANAGED"},
            {"name": "nonsense", "keyType": "USER_MANAGED"},
        ]} if keys else {"keys": []}
    data[f"https://apikeys.googleapis.com/v2/projects/{PROJECT}/locations/global/keys"] = {
        "keys": [{
            "name": API_KEY_NAME, "uid": API_KEY_UID, "displayName": "browser key",
            "createTime": "2026-02-01T00:00:00Z", "updateTime": "2026-02-02T00:00:00Z",
            "restrictions": {"browserKeyRestrictions": {"allowedReferrers": ["*.example.com"]},
                             "apiTargets": [{"service": "maps.googleapis.com"}]},
        }]
    }
    if secrets:
        data[f"https://secretmanager.googleapis.com/v1/projects/{PROJECT}/secrets"] = {
            "secrets": [{"name": SECRET, "createTime": "2026-01-05T00:00:00Z",
                         "rotation": {"nextRotationTime": "2026-07-05T00:00:00Z"},
                         "labels": {"team": "platform"}}]
        }
        data[f"https://secretmanager.googleapis.com/v1/projects/{PROJECT}/locations"] = {
            "locations": [{"name": f"projects/{PROJECT}/locations/{name}"}
                          for name in (*locations, "global")]
        }
        data["https://secretmanager.europe-west4.rep.googleapis.com/v1/projects/"
             f"{PROJECT}/locations/europe-west4/secrets"] = {
            "secrets": [{"name": REGIONAL_SECRET, "createTime": "2026-01-06T00:00:00Z"}]
        }
        data[f"https://secretmanager.googleapis.com/v1/{SECRET}/versions"] = {
            "versions": [
                {"name": SECRET + "/versions/2", "state": "ENABLED",
                 "createTime": "2026-03-01T00:00:00Z"},
                {"name": SECRET + "/versions/1", "state": "DESTROYED",
                 "createTime": "2026-01-05T00:00:00Z", "destroyTime": "2026-03-01T00:00:00Z"},
                {"name": SECRET + "/versions/9", "state": "PENDING"},
            ]
        }
        data["https://secretmanager.europe-west4.rep.googleapis.com/v1/"
             f"{REGIONAL_SECRET}/versions"] = {
            "versions": [{"name": REGIONAL_SECRET + "/versions/1", "state": "ENABLED"}]
        }
    return data


def spec(**overrides):
    body = {
        "schema_version": 2, "name": "gcp inventory", "provider": "gcp",
        "origin": "https://googleapis.com", "edition": "cloud", "tenant": "", "auth_type": "adc",
        "scopes": [{"kind": "project", "id": PROJECT}],
        "capabilities": ["inventory", "vault_metadata"],
        "options": {"mode": "inventory", "page_size": 100},
        "max_records": 5000, "max_requests": 500, "max_pages": 50,
    }
    options = {**body["options"], **overrides.pop("options", {})}
    return MetadataConnectionSpec.model_validate({**body, **overrides, "options": options})


def drain(pages, *, limit=200):
    """Collect every record and the final page from a collect_pages generator."""
    records, final = [], None
    for seen, page in enumerate(pages, start=1):
        if seen > limit:
            raise AssertionError("the adapter produced more pages than expected")
        records.extend(page.records)
        if page.status is not None:
            final = page
    return records, final
