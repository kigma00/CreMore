"""Synthetic event routing must agree with the approved scan scope."""

from types import SimpleNamespace
from uuid import UUID

import pytest

from cremore.scanning.triggers import _event_root
from cremore_notion_provider.source import approved_pages
from cremore_notion_provider.webhooks import targets

PARENT = str(UUID(int=10))
CHILD = str(UUID(int=11))
OTHER = str(UUID(int=12))


def root(mode="PAGE_ONLY", resource_type="NOTION_PAGE", **fields):
    return {"resource_id": "parent", "provider_resource_id": PARENT,
            "resource_type": resource_type, "page_mode": mode,
            "descendant_ids": [CHILD], **fields}


@pytest.mark.parametrize("mode", ["PAGE_ONLY", "PAGE_WITH_DESCENDANTS", None])
@pytest.mark.parametrize("page", [PARENT, CHILD, OTHER])
def test_page_targets_match_approved_pages(mode, page):
    selected = root(mode)
    plan = SimpleNamespace(roots=[selected])
    result = list(targets(plan, {"entity_id": page, "type": "page.content_updated"}))
    assert result == ([{"resource_id": "parent", "page_ids": [page]}]
                      if page in approved_pages(selected) else [])


def test_page_only_stale_descendant_does_not_abort_other_approved_root():
    plan = SimpleNamespace(roots=[root(), root(resource_id="child", provider_resource_id=CHILD,
                                              descendant_ids=[])])
    events = list(targets(plan, {"entity_id": CHILD, "type": "page.content_updated"}))
    # This is the validation used by enqueue_event for each target in a delivery.
    for event in events:
        _event_root(plan, event)
    assert events == [{"resource_id": "child", "page_ids": [CHILD]}]


@pytest.mark.parametrize("event_type", ["data_source.content_updated", "database.content_updated"])
def test_data_source_events_and_selected_rows_remain_supported(event_type):
    plan = SimpleNamespace(roots=[root("DATA_SOURCE_SELECTED_PAGES", "NOTION_DATA_SOURCE")])
    assert list(targets(plan, {"entity_id": PARENT, "type": event_type})) == [
        {"resource_id": "parent", "page_ids": []}]
    assert list(targets(plan, {"entity_id": CHILD, "type": "page.content_updated"})) == [
        {"resource_id": "parent", "page_ids": [CHILD]}]
    assert list(targets(plan, {"entity_id": OTHER, "type": "page.created"})) == []


def test_descendant_identity_normalization_is_preserved():
    plan = SimpleNamespace(roots=[root("PAGE_WITH_DESCENDANTS", descendant_ids=[CHILD.replace("-", "").upper()])])
    assert list(targets(plan, {"entity_id": CHILD, "type": "page.content_updated"})) == [
        {"resource_id": "parent", "page_ids": [CHILD]}]
