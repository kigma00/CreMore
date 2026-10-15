"""Documented Bitbucket Deploy Key responses must reach the common inventory."""

import uuid
from unittest.mock import Mock
from urllib.parse import urlsplit

import pytest

from cremore.coverage.metadata_models import MetadataFinish, metadata_contract
from cremore.coverage.metadata_store import MetadataStore
from cremore.coverage.metadata_stream import batches_for
from cremore.db.repository import InMemoryRepository
from cremore.db.sql import SqlRepository, create_all, make_engine
from cremore_atlassian_provider.metadata.adapter import validate_record

from .output_samples import response
from .test_bitbucket import PUBLIC_KEY
from .test_collector_cli import Response
from .test_common_adapter import collect, spec


@pytest.mark.parametrize("backend", ["memory", "sqlite"])
def test_project_and_repository_deploy_keys_survive_projection_and_storage(backend):
    engine = make_engine("sqlite:///:memory:") if backend == "sqlite" else None
    if engine is not None:
        create_all(engine)
    repo = SqlRepository(engine) if engine is not None else InMemoryRepository()
    config = spec("bitbucket")

    def reply(request, **kwargs):
        path = urlsplit(request.full_url).path
        if path.endswith("/projects"):
            return Response({"values": [{"type": "project", "key": "META", "uuid": "project-id"}]})
        if path.endswith("/deploy-keys"):
            # The numeric ID is scoped to its parent, not globally unique.
            return Response({"values": [{"id": 1234, "key": PUBLIC_KEY,
                                         "label": "Synthetic key", "type": "deploy_key"}]})
        if path.endswith("/deploy-keys/1234"):
            return Response({"id": 1234, "key": PUBLIC_KEY, "type": "deploy_key"})
        return response(request, **kwargs)

    try:
        opener = Mock()
        opener.open.side_effect = reply
        pages, records = collect(config, opener)
        operations = {"project-deploy-keys", "repository-deploy-keys",
                      "project-deploy-key-detail", "repository-deploy-key-detail"}
        keys = [record for record in records if record.record_type == "entity_observation"
                and record.provenance.operation in operations]
        assert {record.provenance.operation for record in keys} == operations
        assert len(keys) == 4
        assert all(record.identity.kind == "public_key" for record in keys)
        assert len({record.identity.object_id for record in keys}) == 2
        assert all(validate_record(config, record) for record in records)

        store = MetadataStore(repo)
        connection, _ = store.create(config, "test")
        run = store.start(connection["id"], 1, str(uuid.uuid4()), metadata_contract(config).model_dump())
        batches = list(batches_for(records, 0))
        for batch in batches:
            store.append(connection["id"], run["id"], batch, trusted_discovery=True)
        store.finish(connection["id"], run["id"], MetadataFinish(
            batch_count=len(batches), item_count=len(records), status=pages[-1].status,
            reasons=pages[-1].reasons,
        ))
        listed = store.inventory(connection_id=connection["id"], object_kind="public_key")["items"]
        assert {record.identity.object_id for record in keys} <= {row["object_id"] for row in listed}
    finally:
        if engine is not None:
            engine.dispose()
