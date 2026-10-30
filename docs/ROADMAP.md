# Roadmap

Planned milestones; features and timelines are targets, not claims of current availability.

Command names below are retained from the proposed roadmap and do not rename the existing LeakyBucket CLI.


## v1.1 — "It works" (weeks 1–4)

Implementation and supported protocol boundaries: [observability guide](OBSERVABILITY.md).

- Single-provider LLM call logging (OpenAI, Ollama, Anthropic)
- Real-time CLI trace view: prompt → response → token count → latency → cost, with live terminal updates
- Terminal timeline with detailed spans (tool calls, retries, streaming chunks)
- Docker Compose one-liner + govern start CLI
- REST API for querying traces (filter by model, timestamp, cost threshold)
- SQLite storage (zero-config) + optional Postgres
- Basic policy engine: YAML rules, hot-reload, govern policy validate
- Slack webhook alerts on cost/latency threshold breach
- MIT license, documented CLI quickstart, docker compose up → headless service
- GitHub Actions CI: lint, test, build image on push

## v1.2 — "It's useful" (weeks 5–8)

- Multi-provider: HuggingFace, Azure OpenAI, Bedrock, Groq, Mistral
- Cost tracking: per-model, per-team, per-day, per-project with spend forecasting
- Team & project hierarchy (org → team → project → model)
- Policy-as-code v1: declarative YAML with CEL expressions
- block, redact, warn, route, escalate actions
- Pattern matching (regex, keyword, semantic similarity)
- Conditional logic (if model == X AND tokens > Y)
- Alerting: Slack, Discord, email, PagerDuty, generic webhook
- Configurable cooldowns, anti-flapping, alert grouping
- RBAC: admin / operator / viewer roles
- Scoped API keys (per-team, per-model, expiring)
- OpenTelemetry export (traces + metrics to any OTel collector)
- Grafana dashboard JSON (importable, pre-built panels)
- govern replay CLI: re-run a trace against a different model/policy
- Rate limiting middleware (per-key, per-team, per-model)
- CLI: govern trace <id>, govern cost --last 7d, govern policy test <rule>

## v1.3 — "It's a security tool" (weeks 9–13)

- Prompt injection detector (direct + indirect)
- Rule-based + ML classifier (fine-tuned DistilBERT or similar)
- Confidence scoring, false-positive tuning via feedback loop
- Action: block / quarantine / flag for review
- PII / sensitive data leakage detection
- Regex + NER for: emails, SSNs, API keys, credit cards, medical records
- Auto-redaction before response delivery
- Configurable: which fields to redact, which to block on
- System prompt leakage detection
- Fingerprint matching on outputs (hash + semantic similarity)
- Alert if model echoes back system prompt fragments
- Tool call guardrails
- Allow/deny lists per agent, per tool, per argument pattern
- Pre-execution validation: sandbox check, permission check, cost check
- Post-execution validation: output size, schema compliance
- Action chain depth limit + elapsed time limit (runaway loop protection)
- Token budget enforcement
- Per-request, per-session, per-day, per-month caps
- Hard stop vs. soft warning modes
- Budget allocation across teams/projects
- OWASP LLM Top 10 test suite
- CLI: govern check --suite owasp-llm --target <endpoint>
- Automated attack vectors per category (LLM01–LLM10)
- Pass/fail report (JSON, HTML, Markdown)
- CI-friendly exit codes
- Interactive policy testing (CLI)
- Test prompts against active policies in real time
- See exactly which rule fired, what action was taken
- A/B test: same prompt, different policy versions
- Shadow AI discovery
- Network scan for unregistered LLM endpoints
- MCP server inventory (what's exposed, what's not)
- Alert on new/unauthorized model endpoints appearing

## v1.4 — "It's enterprise-ready" (weeks 14–18)

- Immutable audit trail
- Every model call, policy decision, tool invocation, and admin action logged
- HMAC-chained (each entry signed with previous entry's hash)
- Export: JSON, CSV, Parquet
- Tamper detection: govern audit verify --from <timestamp>
- Compliance packs
- NIST AI RMF: automated evidence collection + gap analysis
- EU AI Act: risk classification, documentation requirements, logging mandates
- ISO 42001: AI management system controls mapped to your config
- SOC 2 Type II: audit log retention, access control evidence
- Each pack = YAML policy + report template + evidence collector
- AI BOM / SBOM generation
- Inventory: models (name, version, weights, license), datasets, dependencies
- Output: CycloneDX JSON + SPDX
- govern bom generate --output bom.json
- Diff between versions: govern bom diff v1 v2
- Advanced RBAC + policy inheritance
- Per-model, per-tool, per-data-scope, per-region permissions
- Policy inheritance: org → team → project (child overrides parent)
- SSO: SAML, OIDC, LDAP
- Session management: MFA, IP allowlisting, device binding
- Executive reporting
- Auto-generated PDF/Markdown/HTML compliance reports
- Scheduled: daily/weekly/monthly, sent to stakeholders
- CLI reports: risk posture over time, incident frequency, MTTR
- Data retention & lifecycle
- Configurable retention per data class (PII: 30d, audit: 1yr, etc.)
- Auto-purge with confirmation audit log
- Legal hold: freeze deletion on specific traces
- High availability
- Multi-node deployment (stateless workers + shared Postgres)
- govern cluster subcommand for managing nodes
- Health checks, graceful degradation, dead-letter queue for failed alerts

## v1.5 — "It's a platform" (weeks 19–24)

- CI/CD integration
- GitHub Action: govern/action@v1 — runs OWASP suite + policy checks on PR
- GitLab CI: .govern.yml config
- Blocks merge/deploy on failed security tests
- Caching: only re-test changed prompts/models
- Plugin architecture
- Python SDK: govern.plugins package
- Custom detectors: implement Detector interface, register via entry point
- Custom scorers: plug into risk scoring engine
- Custom alert sinks: forward to any system (SIEM, SOAR, custom)
- Plugin marketplace (GitHub-based, govern plugin install <name>)
- Agent fleet control plane
- @govern.control() decorator for LangChain, CrewAI, AutoGen, semantic-kernel
- Centralized policy enforcement across all agents in a fleet
- Agent registry: who's running, what they can do, what they've done
- Kill switch: govern agent stop <id> — immediate, audited
- Agent-to-agent communication monitoring (detect lateral exfiltration)
- Risk scoring engine
- 0–100 score per agent, per model, per deployment
- Factors: severity of last incident, frequency, recency, blast radius, data sensitivity
- Transparent formula (documented, configurable weights)
- Trending: risk posture over time per team/project
- MCP server integration
- Expose governance as an MCP server endpoint
- Any MCP client can query: "is this prompt safe?", "what's my budget?", "what's the risk score?"
- Bidirectional: MCP server can push policy updates to connected agents
- Multi-tenant SaaS mode
- govern deploy --mode saas — adds tenant isolation, billing hooks, self-serve signup
- Per-tenant data isolation (row-level security)
- Customizable terminal output
- SDKs
- Python (first-class), TypeScript, Go
- govern-sdk — instrument your app in 3 lines
- Auto-instrumentation for popular frameworks (LangChain, LlamaIndex, DSPy)

## v2.0 — "It's the standard" (weeks 25–30)

- Post-quantum audit receipts
- ML-DSA-65 / ML-DSA-87 signed action logs
- govern audit sign --algorithm ml-dsa-65
- Verification: govern audit verify --receipt <file>
- Long-term tamper evidence (survives quantum break of current HMAC)
- Drift detection
- Data drift: input distribution shift (PSI, KL divergence)
- Model drift: output distribution shift over time
- Concept drift: task performance degradation
- Alert + auto-rollback suggestion
- Full observability stack integration
- Grafana: native dashboard + data source plugin
- Jaeger/Tempo: trace correlation with your LLM traces
- Prometheus: metrics endpoint (cost, latency, error rate, policy hits)
- Loki: structured log export
- Terraform / Pulumi provider
- govern_project, govern_policy, govern_team, govern_api_key resources
- Infrastructure-as-code for your entire governance setup
- State management, drift detection on infra
- Benchmarking & leaderboard
- govern bench — run standard evals against your guarded pipeline
- Compare: raw model vs. guarded model (latency, accuracy, safety)
- Publish results: govern bench publish
- Contribution infrastructure
- govern plugin new <name> — scaffold a new plugin
- govern policy new <name> — scaffold a new policy pack
- Example repo: 20+ working examples (each a standalone runnable project)
- "Building with Govern" tutorial series (6-part, 10 min each)
- Contributor docs: architecture, code style, PR checklist
- Public roadmap + changelog
- GitHub Projects board (public)
- Auto-generated changelog from conventional commits
- Monthly "What's new" blog post (even if small)
