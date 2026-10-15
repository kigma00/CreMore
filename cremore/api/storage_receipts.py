"""Administrative storage records; collector tokens cannot assert new links."""

import uuid
from typing import Literal

from fastapi import Depends, Query

from cremore.coverage.storage_receipts import StorageReceiptInput, StorageReceiptStore


def register_storage_receipt_routes(app, repo, require_auth, require_role):
    store = StorageReceiptStore(repo)
    admin = require_role("admin")

    @app.get("/api/v1/coverage/storage-receipts")
    def receipts(offset: int = Query(default=0, ge=0), limit: int = Query(default=50, ge=1, le=100),
                 issuer_entity_id: uuid.UUID | None = None, issuer_connection_id: uuid.UUID | None = None,
                 issuer_identifier: str = Query(default="", max_length=1024), _actor=Depends(require_auth)):
        return store.list(offset=offset, limit=limit, issuer_entity_id=issuer_entity_id,
                          issuer_connection_id=issuer_connection_id, issuer_identifier=issuer_identifier)

    @app.post("/api/v1/coverage/storage-receipts", status_code=201)
    def create(body: StorageReceiptInput, actor=Depends(admin)):
        return store.create(body, actor)

    @app.post("/api/v1/coverage/storage-receipts/{receipt_id}/revoke")
    def revoke(receipt_id: uuid.UUID, actor=Depends(admin)):
        return store.revoke(receipt_id, actor)

    @app.get("/api/v1/coverage/storage-receipts/connections")
    def connections(_actor=Depends(admin)):
        return store.connection_choices()

    @app.get("/api/v1/coverage/storage-receipts/connections/{connection_id}/runs")
    def runs(connection_id: uuid.UUID, offset: int = Query(default=0, ge=0),
             limit: int = Query(default=20, ge=1, le=100), _actor=Depends(admin)):
        return store.run_page(connection_id, offset=offset, limit=limit)

    @app.get("/api/v1/coverage/storage-receipts/observations")
    def observations(run_id: uuid.UUID, role: Literal["issuer", "vault"],
                     offset: int = Query(default=0, ge=0), limit: int = Query(default=100, ge=1, le=100),
                     _actor=Depends(admin)):
        return store.candidates(run_id, role=role, offset=offset, limit=limit)
