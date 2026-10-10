"""Executable coverage for rules embedded in each detector module."""
import base64
import codecs
import importlib
import urllib.parse
from pathlib import Path
import pytest

from firewall.core.events import (
    Actor, RetrievedDoc, SecurityEvent, Source, SourceKind, ToolCall, ToolDefinition,
)
from firewall.util.security_rules import RuleCase, inspection_views

MODULES = [p.stem for p in Path(__file__).resolve().parents[1].joinpath('firewall/detectors').glob('*.py')
           if p.stem != '__init__']


def variants(case):
    """Expand canonical fixtures at test time, keeping runtime modules compact."""
    text = case.text
    transforms = {
        "plain": text,
        "uppercase": text.upper(),
        "mixed_case": ''.join(c.upper() if i % 2 else c.lower() for i, c in enumerate(text)),
        "fullwidth": ''.join(chr(ord(c) + 0xFEE0) if '!' <= c <= '~' else c for c in text),
        "zero_width": '\u200b'.join(text),
        "base64": base64.b64encode(text.encode()).decode(),
        "hex": text.encode().hex(),
        "url_encoded": urllib.parse.quote(text),
        "html_entities": ''.join(f'&#{ord(c)};' for c in text),
        "double_url": urllib.parse.quote(urllib.parse.quote(text), safe=''),
        "rot13": codecs.encode(text, 'rot13') + ' Nqqvgvbany pbagrkg sbe guvf qbphzrag vf cebivqrq nf qrfpevcgvir cynva grkg sbe vafcrpgvba.',
        "tabs": text.replace(' ', '\t'),
    }
    for name, value in transforms.items():
        yield RuleCase(case.name + ':' + name, value, case.expect_match)


def cases():
    for name in sorted(MODULES):
        module = importlib.import_module('firewall.detectors.' + name)
        for rule in module.SECURITY_RULES:
            for case in rule.cases:
                expanded = variants(case) if case.name in ('attack_plain', 'benign_plain') else (case,)
                for variant in expanded:
                    yield pytest.param(rule, variant, id=f'{name}:{rule.rule_id}:{variant.name}')


@pytest.mark.parametrize('rule,case', list(cases()))
def test_rule_examples(rule, case):
    matched = any(rule.compiled.search(view) for view in inspection_views(case.text))
    assert matched == case.expect_match


@pytest.mark.parametrize('name', MODULES)
def test_rules_are_wired_into_detector(name):
    module = importlib.import_module('firewall.detectors.' + name)
    detector_type = next(value for key, value in vars(module).items()
                         if isinstance(value, type) and key.endswith('Detector')
                         and value.__module__ == module.__name__)
    detector = detector_type()
    for rule in module.SECURITY_RULES:
        attack = rule.cases[0].text
        event = SecurityEvent(actor=Actor(tenant='t', authenticated=True),
                              input_text=attack, output_text=attack,
                              tool_call=ToolCall('test', {'text': attack}),
                              tool_def=ToolDefinition('test', description=attack),
                              context_docs=[RetrievedDoc('d', attack, Source(
                                  SourceKind.RAG_DOCUMENT, origin='test', tenant='t'))])
        detections = detector.scan(event)
        assert any(d.subcategory == rule.rule_id for d in detections), rule.rule_id


def test_rule_catalog_has_unique_ids_and_both_outcomes():
    for name in MODULES:
        rules = importlib.import_module('firewall.detectors.' + name).SECURITY_RULES
        assert len({rule.rule_id for rule in rules}) == len(rules)
        for rule in rules:
            assert {case.expect_match for case in rule.cases} == {False, True}
