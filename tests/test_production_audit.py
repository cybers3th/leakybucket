import json

import pytest

from firewall import Gateway
from firewall.core.events import Actor, SecurityEvent, ToolCall
from firewall.serve.signed_audit import SignedAuditLog

KEY = b'audit-test-key-01234567890123456789'


def event():
    return SecurityEvent(actor=Actor(user_id='u', metadata={'credential': 'secret-value'}),
                         tool_call=ToolCall(tool='lookup', arguments={'secret': 'private-value'}))


def test_signed_audit_redaction_retention_and_persistent_sequence(tmp_path):
    path = tmp_path / 'audit.jsonl'
    audit = SignedAuditLog(path=path, key=KEY, max_records=2)
    for _ in range(5):
        audit.write(event())
    assert len(audit.records) == 2
    assert audit.verify()[0]
    audit.close()
    data = path.read_text()
    assert 'secret-value' not in data and 'private-value' not in data
    audit = SignedAuditLog(path=path, key=KEY)
    record = audit.write(event())
    assert record['seq'] == 5
    assert audit.verify()[0]
    audit.close()


def test_persistent_audit_requires_key_and_exclusive_owner(tmp_path):
    path = tmp_path / 'audit.jsonl'
    with pytest.raises(ValueError, match='externally managed'):
        SignedAuditLog(path=path)
    log = SignedAuditLog(path=path, key=KEY)
    try:
        with pytest.raises(RuntimeError, match='exclusive'):
            SignedAuditLog(path=path, key=KEY)
    finally:
        log.close()


def test_tampering_wrong_key_and_truncated_tail_prevent_restart(tmp_path):
    path = tmp_path / 'audit.jsonl'
    audit = SignedAuditLog(path=path, key=KEY)
    audit.write(event())
    audit.close()
    with pytest.raises(ValueError):
        SignedAuditLog(path=path, key=b'wrong-key-' * 4)
    original = path.read_text()
    record = json.loads(original)
    record['decision'] = 'modified'
    path.write_text(json.dumps(record) + '\n')
    with pytest.raises(ValueError):
        SignedAuditLog(path=path, key=KEY)
    path.write_text(original + '{"truncated":')
    with pytest.raises(ValueError):
        SignedAuditLog(path=path, key=KEY)


def test_audit_failure_is_not_a_successful_inspection(tmp_path):
    audit = SignedAuditLog(path=tmp_path / 'audit.jsonl', key=KEY)
    gateway = Gateway(audit_log=audit)
    audit.close()
    with pytest.raises(RuntimeError, match='closed'):
        gateway.process_input(SecurityEvent(input_text='Hello'))


def test_synchronous_sink_is_used_and_shipping_failure_is_visible():
    class Sink:
        def __init__(self):
            self.records = []
        def ship(self, record):
            self.records.append(record)
    sink = Sink()
    log = SignedAuditLog(key=KEY, siem=sink, async_ship=False)
    log.write(event())
    assert len(sink.records) == 1
    log.close()
    class Broken:
        def ship(self, record):
            raise OSError('unavailable')
    log = SignedAuditLog(key=KEY, siem=Broken(), async_ship=False)
    with pytest.raises(OSError):
        log.write(event())
    with pytest.raises(RuntimeError, match='unhealthy'):
        log.write(event())
    log.close()


def test_audit_health_tracks_failures_and_shutdown():
    log = SignedAuditLog(key=KEY)
    assert log.healthy
    log.close()
    assert not log.healthy


def test_audit_does_not_retain_schema_embedded_literals():
    from firewall.core.events import ToolDefinition
    log = SignedAuditLog(key=KEY)
    ev = event()
    ev.tool_def = ToolDefinition('lookup', input_schema={'properties': {'token': {'const': 'schema-private-value'}}})
    record = log.write(ev)
    assert 'schema-private-value' not in json.dumps(record)
    log.close()
