import pytest

from firewall.enforcement.conntrack import ConnTracker, ConnectionRejected, ConnectionState


def ready(tracker, tenant='a', identity='c'):
    tracker.open(tenant, identity, ('127.0.0.1', 1234))
    tracker.bind(tenant, identity, 'ai.example', 443)
    tracker.establish(tenant, identity)


def test_connection_lifecycle_and_byte_counts():
    tracker = ConnTracker()
    ready(tracker)
    tracker.begin('a', 'c', 'f')
    tracker.account('a', 'c', 'f', 'request', 20)
    tracker.account('a', 'c', 'f', 'response', 30)
    record = tracker.lookup('a', 'c')
    assert (record.requests, record.in_flight, record.request_bytes, record.response_bytes) == (1, 1, 20, 30)
    tracker.finish('a', 'c', 'f')
    assert tracker.lookup('a', 'c').in_flight == 0
    tracker.close('a', 'c')
    assert tracker.snapshot()['active'] == 0


def test_tenant_and_flow_ownership_cannot_cross():
    tracker = ConnTracker()
    ready(tracker, 'a')
    ready(tracker, 'b')
    tracker.begin('a', 'c', 'f')
    with pytest.raises(ConnectionRejected):
        tracker.account('b', 'c', 'f', 'response', 10)
    tracker.finish('b', 'c', 'f')
    assert tracker.lookup('a', 'c').in_flight == 1
    tracker.close('b', 'c')
    assert tracker.lookup('a', 'c').state == ConnectionState.ESTABLISHED


def test_target_change_blocks_connection():
    tracker = ConnTracker()
    ready(tracker)
    with pytest.raises(ConnectionRejected):
        tracker.bind('a', 'c', 'other.example', 443)
    with pytest.raises(ConnectionRejected):
        tracker.begin('a', 'c', 'f')


def test_connection_and_request_capacity_do_not_evict_active_state():
    tracker = ConnTracker(max_connections=2, max_per_tenant=1, max_in_flight=1)
    ready(tracker)
    with pytest.raises(ConnectionRejected):
        tracker.open('a', 'other', ('127.0.0.1', 1))
    ready(tracker, 'b')
    with pytest.raises(ConnectionRejected):
        tracker.open('c', 'other', ('127.0.0.1', 1))
    tracker.begin('a', 'c', 'f')
    with pytest.raises(ConnectionRejected):
        tracker.begin('a', 'c', 'f2')
    with pytest.raises(ConnectionRejected):
        tracker.begin('a', 'c', 'f')
    tracker.finish('a', 'c', 'f')
    tracker.begin('a', 'c', 'f2')


def test_expiry_removes_flows_and_cannot_reanimate_old_connection():
    now = [0]
    tracker = ConnTracker(idle_timeout=10, max_lifetime=15, clock=lambda: now[0])
    ready(tracker)
    tracker.begin('a', 'c', 'f')
    now[0] = 10
    assert tracker.snapshot()['active'] == 0
    assert tracker.snapshot()['in_flight'] == 0
    with pytest.raises(ConnectionRejected):
        tracker.account('a', 'c', 'f', 'response', 1)
    ready(tracker)
    for moment in (15, 20, 24):
        now[0] = moment
        tracker.bind('a', 'c', 'ai.example', 443)
    now[0] = 25
    with pytest.raises(ConnectionRejected):
        tracker.lookup('a', 'c')


def test_byte_budget_blocks_and_records_are_not_mutable_handles():
    tracker = ConnTracker(max_bytes=10)
    ready(tracker)
    tracker.lookup('a', 'c').host = 'changed.example'
    assert tracker.lookup('a', 'c').host == 'ai.example'
    tracker.begin('a', 'c', 'f')
    tracker.account('a', 'c', 'f', 'request', 6)
    with pytest.raises(ConnectionRejected):
        tracker.account('a', 'c', 'f', 'response', 5)
    assert tracker.snapshot()['blocked'] == 1


def test_new_connection_cannot_send_requests_before_tls():
    tracker = ConnTracker()
    tracker.open('a', 'c', ('127.0.0.1', 1))
    with pytest.raises(ConnectionRejected):
        tracker.begin('a', 'c', 'f')
    with pytest.raises(ConnectionRejected):
        tracker.establish('a', 'c')
