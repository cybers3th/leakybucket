# Changelog

## 1.1.0rc1 — 2026-10-31 (prerelease)

- Require the patched Brotli, Tornado and pyasn1 TLS dependency combination and refresh hashed locks.
- Add provider diagnostics with `doctor`, direct guarded requests with `chat`, and `--version`.
- Make running-service configuration changes explicit instead of silently ignoring them.

- Initialize persistent user configuration and credentials on local start, independent of the working directory.
- Run local startup in the background with locked process ownership, readiness checks and a stop command.
- Preserve successful upstream/policy selections and make trace inspection select the latest request by default.

- Add terminal trace listing, inspection, live watch and service status with tenant-scoped APIs.
- Persist metadata and optional delivered content in SQLite or PostgreSQL.
- Record provider/stream spans, reported usage and explicitly configured cost estimates.
- Add validated YAML block/warn policies, atomic reloads and fail-closed invalid configuration.
- Add bounded Slack threshold alerts and local credential bootstrap.
- Add `leakybucket start`, `policy validate`, compatible `govern` aliases and container packaging.

- Add tenant-scoped connection tracking with expiry, target binding, and request/byte budgets.
- Add an opt-in authenticated TLS interception gateway for exact custom JSON API endpoints.
- Inspect JSON strings and noncredential headers before forwarding either direction.
- Pin validated DNS destinations while preserving upstream TLS hostname verification.
- Add isolated CA generation, private-key checks, optional TLS dependencies, and real HTTPS tests.
- Reject unreviewed protocols and document client trust, routing, pinning, and QUIC boundaries.

## 0.3.0 — 2026-10-20

### Serving and operational enforcement

- Require verified proxy identities by default and separate client and upstream credentials.
- Add scoped service-token authentication and an environment-configured serving entry point.
- Bound HTTP requests, inspection admission, queue residence, request sizes, and user quotas.
- Retain worker capacity after cancellation or timeout until work actually exits.
- Share deadlines across semantic carriers and stop expired tool work before execution.
- Add bounded classifier admission, an outage circuit, and model-service authentication.
- Parse and verify buffered SSE framing before releasing any output; reject unsupported carriers.
- Disable upstream redirects, bound and pool connections, and require HTTPS outside loopback.
- Bound behavior sessions and preserve source trust during semantic deduplication.
- Remove repeated regex decoding views and bound email matching to prevent repeated rescans.
- Redact, bound, exclusively lock, fsync, and verify signed audit storage across restarts.
- Add a hashed Python 3.14 runtime lock, dependency-audit CI, and a restricted systemd unit.
- Add HTTP load/fault probes and regression tests for these boundaries.

### Runtime isolation and inspection

- Restrict the installable distribution to the firewall runtime.
- Remove runnable demos and isolate local model experiments outside the repository.
- Keep canonical rule fixtures in detector modules and generate encoded variants in tests.
- Replace source-line-count requirements with catalog integrity checks.
- Inspect document and source metadata under bounded traversal limits.
- Add a common LangChain serialized-secret-reference signature and explicit AI risk weights.
- Add a ranked threat matrix with coverage gaps and external assurance requirements.
- Bound MCP envelopes and inspection; validate arguments against pinned schemas.
- Track tool-definition drift and optionally correlate responses with requests.
- Scope behavior, rate limits, lineage, and pending requests to actor identities.
- Withhold unsafe tool results and verify buffered output before releasing streams.
- Require verified identity resolution for authenticated proxy requests.
- Add packaging, regression tests, and GitHub CI.

### Application invariants and model evaluation

- Block forged system roles, tested paraphrased authority overrides, and evaluation-response hijacks.
- Add opt-in local semantic injection classification with bounded carrier inspection and failure blocking.
- Add deterministic application output constraints, complete-response schemas, and fail-closed validator callbacks.
- Apply application constraints to buffered streaming and prohibit unverified streaming with configured constraints.
- Inspect shell substitutions in context to avoid treating Python Markdown fences as commands.
- Validate Python tool schemas and callable arguments before execution; enforce network allowlists without an optional global controller.
- Add a model evaluation harness with separate input detection, output detection, application validation, delivery, and tool metrics.
- Add a fixed-budget adaptive attacker with frozen held-out proposals, persistent agent workflow simulations, and uncached latency/memory/failure probes.

## 0.2.0 — 2026-09-06

- Expand the AI attack corpus and framework vulnerability regression fixtures.

## 0.1.0 — 2026-09-03

- Initial firewall, MCP inspection, and attack corpus.
