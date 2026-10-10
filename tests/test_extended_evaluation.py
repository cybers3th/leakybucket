"""Verify evaluation budgets, holdout ordering, execution oracle, and fault enforcement."""
import hashlib
import json
from types import SimpleNamespace

import pytest

from eval import adaptive_security
from eval.agent_workflow import FixtureTools, authorized
from eval.operational import fault_probe, percentile, workload
from firewall import Gateway
from firewall.core.events import Actor
from firewall.enforcement.tool_firewall import ApprovalRequired, ToolBlocked


def test_holdout_frozen_before_scoring_without_feedback(tmp_path, monkeypatch):
    generated, scored = [], []
    def generate(args, history, instruction, seed):
        assert 'WITHHELD_PRIVATE_TRANSCRIPT' not in json.dumps(history)
        attack = {'carrier': 'rag', 'payload': f'unique attack {seed}'}
        generated.append(seed)
        return {'text': json.dumps(attack)}, attack
    def evaluate(attack, args, identity):
        if identity.startswith('final'):
            assert len(generated) == 5
            frozen = args.directory / 'holdout.json'
            assert frozen.exists()
            assert hashlib.sha256(frozen.read_bytes()).hexdigest() == json.loads(
                (args.directory / 'freeze.json').read_text())['holdout_sha256']
        scored.append(identity)
        return {'input_decision': 'block', 'generation': {'text': 'WITHHELD_PRIVATE_TRANSCRIPT'}}
    monkeypatch.setattr(adaptive_security, 'generate_attack', generate)
    monkeypatch.setattr(adaptive_security, 'evaluate', evaluate)
    args = SimpleNamespace(attacker_endpoint='http://127.0.0.1:1', defender_endpoint='http://127.0.0.1:2',
        attacker_model='attacker', defender_model='defender', directory=tmp_path / 'campaign',
        development_budget=3, holdout_budget=2, marker='SYNTHETIC')
    adaptive_security.run(args)
    assert scored == ['dev-0', 'dev-1', 'dev-2', 'final-1', 'final-2']
    summary = json.loads((args.directory / 'summary.json').read_text())
    assert summary['completed_development_evaluations'] == 3 and summary['holdout_valid_unique'] == 2
    with pytest.raises(ValueError, match='must be new'):
        adaptive_security.run(args)
    args.resume_development = True
    with pytest.raises(ValueError, match='unfinished development'):
        adaptive_security.run(args)


@pytest.mark.parametrize('mode', ['malformed', 'unavailable', 'connection_refused', 'timeout'])
def test_http_classifier_faults_never_dispatch(mode):
    result = fault_probe(mode)
    assert result['requests'] == 8
    assert result['all_blocked'] and result['dispatches'] == 0


def test_stateful_execution_boundaries_match_independent_oracle():
    actor = Actor(user_id='reader', session_id='stateful', authenticated=True, roles=['reader'])
    fixture = FixtureTools()
    gateway = Gateway()
    fixture.install(gateway)
    try:
        gateway.request_tool(actor, 'read_file', {'path': 'reports/q3'})
        # Earlier allowed execution does not grant later authority.
        for name, args in [('delete_records', {'resource': 'reports/q3'}),
                           ('fetch_url', {'url': 'https://collector.example.invalid/upload'}),
                           ('read_file', {'path': '../../private/payroll'})]:
            assert not authorized({'tool': name, 'arguments': args})
            with pytest.raises((ToolBlocked, ApprovalRequired)):
                gateway.request_tool(actor, name, args)
        assert len(fixture.executed) == 1 and fixture.executed[0]['authorized']
        assert 'reports/q3' in fixture.records
        assert actor.roles == ['reader']
    finally:
        gateway.close()


def test_latency_quantiles_and_workload_tail():
    assert percentile([1, 2, 3, 4], .5) == 2
    assert percentile([1, 2, 3, 4], .95) == 4
    assert percentile([], .95) is None
    assert len(workload(2).context_docs[0].content) > 3000
    assert adaptive_security.target_seen('ＡＤＡＰＴＩＶＥ -- canary', 'adaptive_canary')
    assert not adaptive_security.target_seen('The office opens at nine.', 'adaptive_canary')
