# AI threat coverage and priorities

Reviewed 2026-10-10. Run `python -m firewall.coverage --self-test --json`
for the ranked machine-readable matrix and executable rule checks.

P0 means prioritize immediate compromise, loss of isolation, or physical hazards;
P1 covers lifecycle, privacy, availability and infrastructure risks; P2 covers
information exposure and content reliability. These are local engineering
priorities, not CVSS scores or a ranking of organizations. Deployment impact
can raise any family to P0.

`runtime` means a runtime enforcement mechanism exists for the inspected path;
`partial` means recognizable signals are inspected but attacks can evade them;
`external` means assurance requires work outside this firewall. None of these
labels is a measured detection rate. Rules only operate on inspected carriers,
and applications must enforce returned decisions.

The matrix covers framework deserialization, artifacts, injection, agent and MCP
abuse, output handling, RAG, training attacks, privacy, exfiltration, infrastructure,
resource exhaustion, perceptual evasion, operational drift and safety assurance.
It explicitly records residual work rather than claiming every AI vulnerability
is detectable. A text firewall cannot validate model weights, prove robustness,
patch a vulnerable dependency or establish mission safety.

The added serialized LangChain secret-reference signature is a defense-in-depth
signal for common JSON payload shapes, not a replacement for patched loaders
or strict deserialization allowlists. Field reordering or nested representations
can evade text signatures. General detector inspection now includes document,
document-source, event-source and tool-result-source metadata under the same
bounded traversal and decoding limits.

## Primary references

- [NIST AI 100-2e2025](https://www.nist.gov/publications/adversarial-machine-learning-taxonomy-and-terminology-attacks-and-mitigations-0): adversarial ML taxonomy, including evasion, poisoning and privacy attacks.
- [OWASP LLM risk project](https://genai.owasp.org/llm-top-10/): application threat categories. The existing README's 2025 list is a versioned baseline, not a claim that it is the latest release.
- [LangChain secret extraction advisory](https://github.com/langchain-ai/langchain/security/advisories/GHSA-c67j-w6g6-q2cm) and [unsafe deserialization advisory](https://github.com/langchain-ai/langchain/security/advisories/GHSA-pjwx-r37v-7724): loader risks requiring dependency fixes and trust boundaries.
- [NASA software quality and AI risk](https://www.nasa.gov/centers-and-facilities/nesc/understanding-risk-artificial-intelligence-and-improving-software-quality/): software engineering and assurance context. NASA is an assurance reference here, not a vulnerability ranking or certification of this project.

Revisit the matrix when dependencies, model capabilities, tools or deployment
impact change. Rule self-tests establish example matching, not security completeness.
