"""A repository catalog row names the connection's own GitHub, never github.com by default."""

import datetime as _dt
import uuid

from cremore.collectors.base import RequestBudget
from cremore_github_provider.catalog import _github


class Resp:
    def __init__(self, status, payload):
        self.status_code, self._payload = status, payload

    def json(self):
        return self._payload


class Denied:
    def get(self, url, headers=None):
        return Resp(404, {})


def test_a_denied_server_reference_links_to_the_server_not_github_com():
    payload = {"base_url": "https://ghes.acme.test/api/v3", "org": "acme", "token": "ghp_t", "reference": "acme/app"}
    rows, completeness = _github(payload, "source", str(uuid.uuid4()), Denied(), _dt.datetime(2026, 10, 1, tzinfo=_dt.UTC),
                                 RequestBudget(5))
    assert completeness == "PARTIAL" and rows[0]["list_visibility"] == "DENIED"
    assert rows[0]["canonical_reference"] == "https://ghes.acme.test/acme/app"
    assert rows[0]["provider_instance_id"] == "ghes.acme.test"
    public, _ = _github({**payload, "base_url": "https://api.github.com"}, "source", str(uuid.uuid4()), Denied(),
                        _dt.datetime(2026, 10, 1, tzinfo=_dt.UTC), RequestBudget(5))
    assert (public[0]["canonical_reference"], public[0]["provider_instance_id"]) == (
        "https://github.com/acme/app", "github.com")
