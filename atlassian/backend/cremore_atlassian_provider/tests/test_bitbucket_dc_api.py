"""DC replay and retry use the shared authenticated metadata API unchanged."""

from cremore.api import metadata_coverage_test as api

from .test_bitbucket_dc import page, run, spec
from .test_bitbucket_dc_replay import later
from .test_collector_http import Response

client = api.client


def finish(client, created, records, status):
    run_id, response = api.submit(client, created, [record.model_dump() for record in records])
    assert response.status_code == 200, response.text
    response = client.post(f"/api/v2/coverage/collector/{created['id']}/runs/{run_id}/finish",
        headers={"X-Cremore-Collector-Token": created["collector_token"]},
        json={"schema_version": 2, "batch_count": 1, "item_count": len(records), "status": status})
    assert response.status_code == 200, response.text
    return run_id


def test_native_export_compare_and_selected_recollection_through_shared_api(client):
    config = spec()
    created = api.create(client, config.model_dump())
    _, before, _ = run(config, [page("old")])
    _, denied, _ = run(config, [Response(b"no", status=403)])
    first = finish(client, created, before, "COMPLETE")
    second = finish(client, created, later(denied), "FAILED")
    exported = client.get(f"/api/v2/coverage/runs/{first}/export?format=native")
    assert exported.status_code == 200, exported.text
    assert exported.json()["snapshots"][0]["environment"] == "data_center"
    compared = client.get(f"/api/v2/coverage/runs/{first}/compare/{second}")
    assert compared.status_code == 200, compared.text
    assert compared.json()["comparison"]["counts"]["observation_unknown"] == 1
    assert compared.json()["comparison"]["counts"]["not_observed"] == 0
    for selection in ({"scope_id": "not-approved"}, {"operations": ["cloud-operation"]}):
        rejected = client.post(f"/api/v2/coverage/connections/{created['id']}/collect",
                               json={"retry_from_run": second, **selection})
        assert rejected.status_code == 409, rejected.text
    complete = client.post(f"/api/v2/coverage/connections/{created['id']}/collect",
                           json={"retry_from_run": first})
    assert complete.status_code == 409
    assert complete.json()["error"] == "BITBUCKET_DC_NO_RECOLLECTION_TARGETS"
    accepted = client.post(f"/api/v2/coverage/connections/{created['id']}/collect",
        json={"retry_from_run": second, "scope_id": "alice", "operations": ["dc-user-http-tokens"]})
    assert accepted.status_code == 202, accepted.text
