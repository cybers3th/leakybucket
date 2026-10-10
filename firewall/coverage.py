"""Inspectable detector coverage manifest and offline rule verification.

Run ``python -m firewall.coverage --self-test --json``. Example strings are
matched as data and are never run as commands or sent over the network.
"""
from __future__ import annotations

import argparse
import importlib
import json
from pathlib import Path

from firewall.util.security_rules import inspection_views
from firewall.threat_matrix import ranked_threats


def report(self_test=False):
    modules = {}
    failures = []
    for path in sorted(Path(__file__).parent.joinpath('detectors').glob('*.py')):
        if path.name == '__init__.py':
            continue
        module = importlib.import_module('firewall.detectors.' + path.stem)
        rules = module.SECURITY_RULES
        modules[path.stem] = {
            'additional_rule_families': len(rules),
            'positive_examples': sum(case.expect_match for rule in rules for case in rule.cases),
            'negative_examples': sum(not case.expect_match for rule in rules for case in rule.cases),
            'rules': [rule.rule_id for rule in rules],
        }
        if self_test:
            for rule in rules:
                for case in rule.cases:
                    detected = any(rule.compiled.search(view) for view in inspection_views(case.text))
                    if detected != case.expect_match:
                        failures.append({'detector': path.stem, 'rule': rule.rule_id,
                                         'case': case.name})
    return {'threat_ranking': ranked_threats(), 'ranking_basis': 'Local impact-based priority; not CVSS or measured recall', 'detectors': modules, 'self_test_requested': self_test,
            'failures': failures, 'passed': not failures if self_test else None}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--self-test', action='store_true')
    parser.add_argument('--json', action='store_true')
    args = parser.parse_args()
    result = report(args.self_test)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        for detector, item in result['detectors'].items():
            print(f"{detector}: {item['additional_rule_families']} additional rule families, "
                  f"{item['positive_examples']} attack / {item['negative_examples']} benign examples")
        for threat in result['threat_ranking']:
            print(f"{threat['priority']} {threat['family']}: {threat['coverage']}")
        if args.self_test:
            print('self-test: ' + ('PASS' if result['passed'] else 'FAIL'))
    return 1 if result['failures'] else 0


if __name__ == '__main__':
    raise SystemExit(main())
