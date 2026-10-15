"""Built-in detectors an administrator turns off: left out of scans, never evidence of removal."""

import pytest

from cremore.config import Settings
from cremore.db.repository import InMemoryRepository
from cremore.detection import ResourceRef, switches
from cremore.detection.engine import EngineConfig
from cremore.scanning import Orchestrator

GH = "ghp_" + "aB3dE5fG7hJ9kL1mN2pQ4rS6tU8vW0xY2zC4"
KEY = b"k" * 32
TOKEN = "switch-api-" + "z" * 32
DETECTOR = "github-token-v1"


def orchestrator(repo):
    return Orchestrator(repo, config=EngineConfig(fingerprint_key=KEY), rule_provider=repo.list_rules)


def scan(orch, text, location="app.py"):
    return orch.scan_resource(text.encode(), ResourceRef(source_type="inline", resource="synthetic", location=location),
                              verify=False)


def test_a_turned_off_detector_finds_nothing_until_it_is_turned_on_again():
    repo = InMemoryRepository()
    orch = orchestrator(repo)
    orch.refresh_rules()
    before = orch.engine.detection_digest
    assert scan(orch, f"token = {GH}").findings
    switches.set_enabled(repo, DETECTOR, False, "admin")
    assert switches.disabled(repo) == {DETECTOR}
    orch.refresh_rules()
    assert orch.engine.detection_digest != before  # cached results and value comparisons follow
    assert not scan(orch, f"other = {GH}", location="b.py").findings
    switches.set_enabled(repo, DETECTOR, True, "admin")
    orch.refresh_rules()
    assert orch.engine.detection_digest == before and scan(orch, f"third = {GH}", location="c.py").findings
    with pytest.raises(ValueError):
        switches.set_enabled(repo, "no-such-detector", False, "admin")


def test_an_exposure_a_turned_off_detector_found_is_not_removed_by_a_rescan():
    repo = InMemoryRepository()
    orch = orchestrator(repo)
    orch.refresh_rules()
    resource = ResourceRef(source_type="github", resource="acme/app", location="app.py")
    connection = __import__("uuid").uuid4()
    first = orch.scan_resource(f"token = {GH}".encode(), resource, source_connection_id=connection, verify=False)
    [exposure_id] = first.exposure_ids
    switches.set_enabled(repo, DETECTOR, False, "admin")
    orch.refresh_rules()
    # The same file read again, fully, without the (now skipped) detector's match.
    orch.reconcile_resource(connection, resource, [], complete=True)
    assert next(e for e in repo.exposures_for_connection(connection) if e.id == exposure_id).status != "REMOVED"
    switches.set_enabled(repo, DETECTOR, True, "admin")
    orch.refresh_rules()
    orch.reconcile_resource(connection, resource, [], complete=True)
    assert next(e for e in repo.exposures_for_connection(connection) if e.id == exposure_id).status == "REMOVED"


def test_the_switch_is_an_administrator_route_and_the_catalog_shows_it():
    from fastapi.testclient import TestClient

    from cremore.api import create_app

    repo = InMemoryRepository()
    client = TestClient(create_app(repo=repo, settings=Settings(AUTH_MODE="local", API_TOKEN=TOKEN,
                                                                FINGERPRINT_KEY=KEY.hex())))
    auth = {"Authorization": f"Bearer {TOKEN}"}
    changed = client.put(f"/api/v1/detection-engine/detectors/{DETECTOR}", headers=auth, json={"enabled": False})
    assert changed.status_code == 200 and changed.json()["enabled"] is False and changed.json()["switched_at"]
    catalog = {d["id"]: d for d in client.get("/api/v1/detection-engine", headers=auth).json()["detectors"]}
    assert catalog[DETECTOR]["enabled"] is False and catalog[DETECTOR]["switched_by"]
    assert catalog[DETECTOR]["category"] == "token" and catalog[DETECTOR]["patterns"]
    assert catalog["aws-access-key-pair-v1"]["enabled"] is True and "switched_by" not in catalog["aws-access-key-pair-v1"]
    # The API's own inline scans follow at once.
    scanned = client.post("/api/v1/scan", headers=auth, json={"text": f"token = {GH}", "source_type": "inline"})
    assert scanned.status_code == 202 and scanned.json()["detections"] == 0
    assert client.put("/api/v1/detection-engine/detectors/nope", headers=auth,
                      json={"enabled": False}).status_code == 404
    assert client.put(f"/api/v1/detection-engine/detectors/{DETECTOR}", headers=auth,
                      json={"enabled": "no"}).status_code == 422


def test_the_customer_side_hasher_compiles_the_same_detectors_as_the_contract():
    from cremore.cli.coverage import execute
    from cremore.coverage.external_vault_test import cli_stack, external, lines
    from cremore.coverage.store import CoverageStore

    repo = InMemoryRepository()
    client = cli_stack(repo)
    switches.set_enabled(repo, DETECTOR, False, "admin")
    connection, token = CoverageStore(repo).create(external(), "admin")
    # A hasher that compiled every built-in would compute another contract and be refused.
    result = execute("http://localhost", connection["id"], token, KEY, client=client,
                     input_stream=lines({"path": "prod/app/aws", "value": "AKIA" + "Q" * 16}))
    assert result["status"] in ("PARTIAL", "COMPLETE")
