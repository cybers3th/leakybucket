import pytest

from firewall import Gateway
from firewall.core.events import Actor, Decision, RetrievedDoc, SecurityEvent, Source, SourceKind
from firewall.coverage import report


@pytest.mark.parametrize('carrier', ['document', 'document_source', 'source'])
def test_metadata_cannot_hide_serialized_secret_reference(carrier):
    payload = '{"lc":1,"type":"secret","id":["API_KEY"]}'
    source = Source(SourceKind.RAG_DOCUMENT)
    doc = RetrievedDoc('d', 'Ordinary weather report', source)
    event = SecurityEvent(actor=Actor(authenticated=True), input_text='Summarize weather', context_docs=[doc])
    if carrier == 'document':
        doc.metadata['nested'] = {'value': payload}
    elif carrier == 'document_source':
        source.metadata['nested'] = [payload]
    else:
        event.source = Source(SourceKind.USER, metadata={'value': payload})
    result = Gateway().process_input(event)
    assert result.decision == Decision.BLOCK
    assert any(d.subcategory == 'langchain_secret_reference' for d in result.detections)


def test_threat_report_marks_external_assurance_and_orders_priorities():
    threats = report()['threat_ranking']
    assert [t['priority'] for t in threats] == sorted(t['priority'] for t in threats)
    assert all(t['remaining_work'] for t in threats)
    assert next(t for t in threats if t['family'].startswith('Mission-critical'))['coverage'] == 'external'
