"""Compatible metadata runs keep native comparison direction and output."""

from types import SimpleNamespace

from cremore_azure_provider.metadata import adapter
from cremore_azure_provider.metadata.azure_key_vault_test import (
    SPEC,
    UPDATED,
    VAULT,
    Vault,
    collect,
    records,
    secret,
    spec,
)

from cremore.api import metadata_coverage_test
from cremore.coverage.collector_runtime import CollectorRuntime

client = metadata_coverage_test.client


def test_azure_compatible_runs_compare_in_chronological_order(client, monkeypatch):
    from cremore.api import metadata_coverage

    created = metadata_coverage_test.create(client, SPEC)
    headers = {"X-Cremore-Collector-Token": created["collector_token"]}
    runs, batches = [], []
    for rows in ([secret("removed"), secret("shared")],
                 [secret("added"), secret("shared", updated=UPDATED + 1)]):
        batch = [item.model_dump(mode="json") for item in records(
            collect(spec(), Vault({"/secrets": {"value": rows}})))]
        run, accepted = metadata_coverage_test.submit(client, created, batch)
        assert accepted.status_code == 200, accepted.text
        finished = client.post(f"/api/v2/coverage/collector/{created['id']}/runs/{run}/finish",
            headers=headers, json={"schema_version": 2, "batch_count": 1,
                                  "item_count": len(batch), "status": "COMPLETE", "reasons": []})
        assert finished.status_code == 200, finished.text
        runs.append(run)
        batches.append(batch)
    response = client.get(f"/api/v2/coverage/runs/{runs[0]}/compare/{runs[1]}")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body == {"schema_version": 2, "before_run_id": runs[0], "after_run_id": runs[1],
                    "comparison": adapter.compare_records(*batches)}
    assert body["comparison"]["added"] == [f"secret:{VAULT}:added"]
    assert body["comparison"]["removed"] == [f"secret:{VAULT}:removed"]
    assert body["comparison"]["changed"] == [{"object_id": f"secret:{VAULT}:shared", "fields": ["updated_at"]}]
    assert client.get(f"/api/v2/coverage/runs/{runs[1]}/compare/{runs[0]}").status_code == 409
    # Unsupported comparisons are refused before loading bounded record pages.
    monkeypatch.setattr(metadata_coverage, "collector_for", lambda provider: CollectorRuntime(adapter=SimpleNamespace()))
    def unexpected_read(*args):
        raise AssertionError("Unsupported comparison loaded records")
    monkeypatch.setattr(metadata_coverage, "bounded_records", unexpected_read)
    unsupported = client.get(f"/api/v2/coverage/runs/{runs[0]}/compare/{runs[1]}")
    assert unsupported.status_code == 409
    assert unsupported.json()["error"] == "METADATA_COMPARISON_UNSUPPORTED"
