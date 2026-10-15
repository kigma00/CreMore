"""Records that discovery registers join the provider connection that asked for them (design 4.5).

An AWS connection whose target says ``adopt_discovered`` takes in the accounts the
Identity Center or Organizations sweep registers in its access mode: each is linked to
the connection and gets what the connection's saved step 4 plans create for its own
accounts (inventory collections, secret store reads). A provider module offers the
records it would take with ``adoptable(repo, connection) -> [{kind, id, target}]``,
``target`` being the connection's target narrowed to that record; records any provider
connection already owns are never offered again.
"""

from __future__ import annotations

import logging

from cremore.onboarding import catalog, children
from cremore.onboarding.store import ProviderConnectionStore, active_plans, atomic

logger = logging.getLogger(__name__)


def adopt(repo, settings, actor: str = "system") -> list[dict]:
    """Take in what discovery registered since the last call; returns what each connection adopted."""
    from cremore.domain.models import FindingEvent

    store = ProviderConnectionStore(repo)
    adopted = []
    for record in store.list():
        if record["status"] != "ACTIVE" or not active_plans(record) or not record["target"].get("adopt_discovered"):
            continue
        module = catalog.module(record["provider"])
        offer = getattr(module, "adoptable", None)
        if not callable(offer):
            continue
        for item in offer(repo, record):
            if store.parent_of(item["kind"], item["id"]) is not None:
                continue
            narrowed = {**record, "target": item["target"]}
            try:
                with atomic(repo) as bound:
                    prepare = getattr(module, "prepare", None)
                    for child in (prepare(narrowed) if callable(prepare) else []):
                        children.create(bound, settings, record, child["purpose"], child, actor)
                    for purpose, plan in active_plans(record).items():
                        for child in module.children(narrowed, purpose, plan):
                            children.create(bound, settings, record, child["purpose"], child, actor)
                    bound.record_finding_event(FindingEvent(
                        target_type="provider_connection", target_id=record["id"], actor=actor,
                        event_type="PROVIDER_CONNECTION_RECORD_ADOPTED", note=f"{item['kind']} {item['id']}"))
            except (children.ChildError, ValueError) as exc:
                # One record that cannot be taken in never stops the others; the next call retries it.
                logger.warning("adopting %s for a provider connection failed: %s", item["kind"],
                               getattr(exc, "code", None) or type(exc).__name__)
                continue
            adopted.append({"provider_connection_id": str(record["id"]), "kind": item["kind"], "id": str(item["id"])})
    return adopted
