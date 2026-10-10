"""Local prioritization, not CVSS, certification, or measured detection recall."""
from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class ThreatFamily:
    family: str
    priority: str
    coverage: str
    controls: tuple[str, ...]
    remaining_work: str


THREATS = (
    ThreatFamily('Framework deserialization and model artifact execution', 'P0', 'partial',
                 ('ai_specific', 'supply_chain', 'tool_security'), 'Patch dependencies; sandbox loaders; verify artifact signatures. Text signatures do not inspect binaries.'),
    ThreatFamily('Tool execution, privilege escalation and destructive actions', 'P0', 'runtime',
                 ('tool_security', 'agentic', 'tool_firewall'), 'Enforce OS permissions and independently approve irreversible actions.'),
    ThreatFamily('Secrets exfiltration and cross-tenant disclosure', 'P0', 'partial',
                 ('sensitive_data', 'network', 'trust'), 'Enforce database tenant authorization and egress at the network layer.'),
    ThreatFamily('Indirect injection, goal hijacking and instruction spoofing', 'P0', 'partial',
                 ('prompt_injection', 'agentic', 'security_rules'), 'Evaluate adaptive paraphrases; text detection cannot prove absence of injection.'),
    ThreatFamily('MCP poisoning, drift, sampling abuse and confused deputy', 'P0', 'runtime',
                 ('mcp', 'tool_firewall'), 'Authenticate transport and pin reviewed server identities.'),
    ThreatFamily('Unsafe downstream output, SQL, shell, templates and browser code', 'P0', 'partial',
                 ('output_security', 'output_validators'), 'Use parameterized queries, escaping and isolated execution.'),
    ThreatFamily('Mission-critical autonomy and physical safety hazards', 'P0', 'external',
                 (), 'Independent safety engineering, hazard analysis, fail-safe design and verification; no NASA certification is implied.'),
    ThreatFamily('Training poisoning, backdoors, adapters and federated updates', 'P1', 'partial',
                 ('poisoning', 'ai_specific', 'supply_chain'), 'Validate training lineage and perform model-level backdoor evaluation.'),
    ThreatFamily('RAG retrieval manipulation, embedding attacks and poisoned memory', 'P1', 'partial',
                 ('rag_security', 'poisoning', 'trust'), 'Enforce retrieval ACLs and validate index provenance and integrity.'),
    ThreatFamily('Agent identity spoofing, communication abuse and cascading failure', 'P1', 'partial',
                 ('agentic', 'behavior', 'mcp'), 'Use cryptographic identities and scoped delegation; exercise recovery.'),
    ThreatFamily('SSRF, metadata access and exposed inference infrastructure', 'P1', 'partial',
                 ('infra_exposure', 'network'), 'Enforce private-network isolation and authenticated inference endpoints.'),
    ThreatFamily('Denial of service, context flooding and unbounded spending', 'P1', 'runtime',
                 ('consumption', 'rate_limits', 'security_rules'), 'Set provider spend caps and distributed quotas.'),
    ThreatFamily('Model extraction, membership inference and training-data privacy', 'P1', 'partial',
                 ('ai_specific', 'behavior', 'rate_limits'), 'Conduct privacy evaluation and apply privacy-preserving training where required.'),
    ThreatFamily('Image, audio, video and sensor adversarial evasion', 'P1', 'external',
                 ('multimodal',), 'OCR/transcription only enables text inspection; evaluate raw perceptual and sensor attacks separately.'),
    ThreatFamily('System prompt disclosure and policy reconnaissance', 'P2', 'partial',
                 ('system_prompt_leak',), 'Keep credentials and authorization rules outside prompts.'),
    ThreatFamily('Misinformation, fabricated evidence and overreliance', 'P2', 'partial',
                 ('misinformation',), 'Validate claims against authoritative evidence and domain experts.'),
    ThreatFamily('Distribution shift, uncertainty and model degradation', 'P1', 'external',
                 (), 'Monitor model performance and uncertainty; validate operational envelopes.'),
    ThreatFamily('Governance, human oversight and change assurance', 'P1', 'external',
                 ('audit', 'signed_audit'), 'Maintain an independent assurance case, reviews and incident response exercises.'),
)


def ranked_threats():
    return [asdict(item) for item in sorted(THREATS, key=lambda item: (item.priority, item.family))]
