"""v0.11.1 behavior at the shared worker boundary, without live credentials."""
import io
import json
from copy import deepcopy

import pytest

from ..adapter import _config, export_records, validate_machine_record, validate_record
from ..config import Config
from ..http import Client, CollectionError, TokenBucket
from ..normalization import record, unpack_facts
from ..storage import Store
from .test_adapter import records, run, spec_for


class Clock:
    """One virtual clock drives global and endpoint permits."""
    def __init__(self):
        self.value = 0.0
    def now(self):
        return self.value
    def sleep(self, seconds):
        self.value += seconds


class Opener:
    """Exercise Client.request itself, not a bypassing fake request method."""
    def __init__(self, clock):
        self.clock, self.times = clock, []
    def open(self, request, timeout):
        self.times.append(self.clock.now())
        response = io.BytesIO(b'{"id": 1}')
        response.headers = {}
        return response


def test_user_rate_limit_and_readiness_use_real_request_path():
    clock = Clock()
    opener = Opener(clock)
    client = Client(Config(requests_per_second=100, burst=1), 'TEST_ONLY',
                    opener=opener, clock=clock.now, sleep=clock.sleep)
    client.request(client.rest_url('/users/1'))
    assert client.deferred_rate_classes() == frozenset({'user_details'})
    client.request(client.rest_url('/projects/1'))
    client.request(client.rest_url('/users/2'))
    assert opener.times == pytest.approx([0.0, 0.01, 2.0])


@pytest.mark.parametrize('token', ['', '안내 문구', 'abc\n', ' abc'])
def test_invalid_auth_fails_before_network(token):
    with pytest.raises(CollectionError, match='PAT'):
        Client(Config(), token)


def test_atomic_permits_do_not_consume_global_while_waiting():
    clock = Clock()
    global_bucket = TokenBucket(2, 1, clock=clock.now, sleep=clock.sleep)
    users = TokenBucket(.5, 1, clock=clock.now, sleep=clock.sleep)
    global_bucket.acquire(users)
    global_bucket.acquire(users)
    assert clock.value == 2
    assert global_bucket.balance == users.balance == 0


def test_queue_discovery_precedes_audit_and_skips_blocked_users():
    store = Store('test')
    audit = store.add_task('audit_plan', '/groups/1/audit_events', {})
    user = store.add_task('user', '/users/1', {})
    token = store.add_task('token_list', '/groups/1/deploy_tokens', {})
    assert store.next_task()['id'] == token
    with store.db:
        store.page_done(store.next_task(), 'page', 0)
    assert store.next_task()['id'] == user
    assert store.next_task(frozenset({'user_details'}))['id'] == audit
    with store.db:
        store.page_done(store.next_task(frozenset({'user_details'})), 'audit', 0)
    assert store.next_task(frozenset({'user_details'}))['id'] == user


def test_queue_index_survives_pages_and_rebuilds_after_rollback():
    store = Store('test')
    store.add_task('user', '/users/1', {})
    store.next_task()
    heap = store._task_heaps
    with store.db:
        store.add_task('token_list', '/groups/1/deploy_tokens', {})
    assert store._task_heaps is heap
    assert store.next_task()['spec']['handler'] == 'token_list'
    with pytest.raises(RuntimeError), store.db:
        store.add_task('group', '/groups/2', {})
        raise RuntimeError('rollback')
    assert len(store.state['tasks']) == 2
    assert store.next_task()['spec']['handler'] == 'token_list'


def test_notes_are_deduplicated_and_transactional_across_checkpoint():
    store = Store('test')
    for _ in range(2):
        for i in range(1000):
            store.note('TEST', {'id': i})
    assert len(store.state['notes']) == 1000
    with pytest.raises(RuntimeError), store.db:
        store.note('ROLLBACK', {})
        raise RuntimeError()
    restored = Store('test', store.checkpoint())
    assert restored.get_setting('coverage_notes') == store.get_setting('coverage_notes')
    assert len(restored.state['notes']) == 1000


def test_audit_disabled_export_is_unknown_not_false_and_replay_is_stable():
    spec = spec_for(audit=False)
    pages = run(spec)
    exported = export_records(records(pages), spec=spec)['inventory']
    assert len(exported) == 12
    for row in exported:
        evidence = row['audit']['creation_evidence']
        assert row['schema_version'] == '1.4'
        assert evidence['status'] == 'not_searched'
        assert evidence['token_creation_time_covered'] is None
    resumed = run(spec, checkpoint=pages[-1].checkpoint, previous=records(pages))
    assert resumed[-1].status == 'COMPLETE'


def test_audit_dates_and_disabled_policy_survive_without_secret_values():
    spec = spec_for(audit=True)
    pages = run(spec)
    result = export_records(records(pages), spec=spec)
    found = [r for r in result['inventory'] if r['audit']['creation_evidence']['status'] == 'found']
    assert found
    assert all(r['audit']['creation_evidence']['stop_reason'] is None for r in found)
    assert 'SYNTHETIC_OPERATOR_AUTH' not in json.dumps(result)
    # Existing explicit full-history policies are preserved during the upgrade.
    assert _config(spec_for(options={'audit_lookback_days': None})).audit_lookback_days is None
    for days in (30, 60, 90, 180):
        assert _config(spec_for(options={'audit_lookback_days': days})).audit_lookback_days == days


@pytest.mark.parametrize('audit', [False, True])
def test_creation_evidence_survives_the_dashboard_storage_boundary(audit):
    spec = spec_for(audit=audit)
    committed = records(run(spec))
    exported = {row['inventory_id']: row for row in export_records(committed, spec=spec)['inventory']}
    stored = [item for item in committed if item['provenance']['operation'] == 'gitlab.native.inventory']
    assert len(stored) == len(exported) == 12
    searched = False
    for item in stored:
        payload = unpack_facts(item['facts'])
        expected = exported[payload['inventory_id']]['audit']['creation_evidence']
        assert payload['audit']['creation_evidence'] == expected
        assert not any(omission['path'].startswith('audit/creation_evidence') for omission in item['omissions'])
        # A real completed range reaches the deepest approved fact level.
        searched |= any(scope['completed_ranges'] for scope in expected['scope_coverage'])
    assert searched is audit


def test_creation_evidence_keeps_value_filters_and_fact_depth_limits():
    spec = spec_for(audit=True)
    payload = deepcopy(export_records(records(run(spec)), spec=spec)['inventory'][0])
    payload['audit']['creation_evidence'].update({
        'raw_secret': 'SYNTHETIC_UNAPPROVED_VALUE',
        'description': 'glpat-' + 'A' * 20,
        'metadata': {'metadata': {'metadata': {'metadata': {'metadata': {'metadata': 'TOO_DEEP'}}}}},
    })
    item = record(spec, spec.scopes[0], 'inventory', payload)
    encoded = item.model_dump_json()
    assert 'SYNTHETIC_UNAPPROVED_VALUE' not in encoded
    assert 'glpat-' not in encoded
    assert 'TOO_DEEP' not in encoded
    assert {omission.reason for omission in item.omissions} >= {
        'UNAPPROVED_METADATA_FIELD', 'INVALID_METADATA_VALUE', 'METADATA_FACT_LIMIT',
    }
    pending = [(fact, 1) for fact in item.facts]
    while pending:
        fact, depth = pending.pop()
        assert depth <= 6
        pending.extend((child, depth + 1) for child in fact.children)


def test_conflicting_audit_fact_paths_are_rejected_without_overwriting():
    from cremore.coverage.metadata_models import MetadataFact

    spec = spec_for(audit=True)
    payload = export_records(records(run(spec)), spec=spec)['inventory'][0]
    item = record(spec, spec.scopes[0], 'inventory', payload)
    assert validate_record(spec, item)
    audit = next(fact for fact in item.facts if fact.name == 'audit')
    audit.children.append(MetadataFact(name='creation_evidence', state='NULL'))
    assert not validate_record(spec, item)
    assert not validate_machine_record(spec, item)
