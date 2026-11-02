# LeakyBucket

**v1.1 prerelease — Linux CLI.** Model weights and provider credentials are not
included. This release candidate is intended for evaluation before deployment.

Install the release candidate with an isolated CLI environment:

```sh
pipx install 'leakybucket-firewall[observe] @ https://github.com/cybers3th/leakybucket/releases/download/v1.1.0-rc.1/leakybucket_firewall-1.1.0rc1-py3-none-any.whl'
leakybucket --version
leakybucket start
leakybucket doctor
```

`doctor` checks the firewall, policy and provider separately. An unavailable model
provider does not mean the firewall itself failed to start. Configure your provider
with `leakybucket start --upstream-url URL` after stopping any running instance.
A `/v1` API address is not a browser page.

LeakyBucket is a Python security inspection layer for LLM applications, agent
tools, retrieved content, and MCP messages. It combines text detectors,
provenance checks, risk scoring, policy decisions, tool permissions, rate limits,
and audit records.

The application must enforce the returned decision before dispatching a request,
executing a tool, or releasing a response. Text inspection does not establish
that a model or application is secure.

## Install

Requires Python 3.10 or later.

```sh
python -m pip install .
```

For HTTP serving and development checks:

```sh
python -m pip install -e '.[test,serve]'
python -m firewall.coverage --self-test
python -m pytest -q --ignore=tests/test_dataset_and_regression.py
```

The distribution contains only `firewall`. Corpus generators, evaluation tools,
and tests stay in the repository as development tooling. Model weights, inference
runtimes, transcripts, generated datasets, and audit output are excluded.

## Manual

```sh
leakybucket man
```

Use `leakybucket man --plain` for unpaged text. To install the native user man page:

```sh
leakybucket man --install
man leakybucket
```

The manual covers every CLI command, inspection modes, files, environment settings,
exit codes and troubleshooting. Read it without starting a service.

## Terminal operations

```sh
python -m pip install -e '.[observe]'
leakybucket start
```

Start works from any directory and initializes a private local configuration.
By default, the proxy targets an Ollama-compatible server at
`http://127.0.0.1:11434/v1`, which must be running separately for model requests.
Use `start --upstream-url URL` to choose another provider. Local startup uses
built-in rules unless a semantic classifier is configured. Then:

```sh
leakybucket status
leakybucket doctor
leakybucket traces --limit 20
leakybucket trace
leakybucket watch
leakybucket stop
leakybucket policy validate
```

Send a prompt directly through the firewall once your provider is available:

```sh
leakybucket chat --model YOUR_MODEL 'Explain why rain forms.'
```

Replace `YOUR_MODEL` with an actual model ID reported by `doctor`.
The CLI shows persisted requests, request timelines through `trace`, provider
spans, token usage, latency and configured cost estimates. Use `--json` for
scripts. Content capture is off by default. There is no browser UI.

See the [operations guide](docs/OBSERVABILITY.md) for provider credentials,
containers, PostgreSQL, reloadable YAML rules, Slack alerts and deployment limits.
The [roadmap](docs/ROADMAP.md) tracks the remaining milestones.

## Integration

`Gateway.process_input` and `Gateway.process_output` inspect `SecurityEvent`
objects. `Gateway.request_tool` uses the tool firewall to enforce registered
permissions and approval requirements. The MCP gateway separately inspects
inbound and outbound JSON-RPC messages against pinned server and tool definitions.

Decisions are `allow`, `sanitize`, `require_approval`, and `block`. Applications
must implement approved sanitization and approval handling; a non-allow decision
is not permission to forward the original content.

See [deployment boundaries](docs/DEPLOYMENT.md) for integration requirements,
authentication, streaming, MCP authorization, and network enforcement.

## Serving

Version 0.3.0 provides an authenticated text proxy with bounded admission,
request deadlines, fail-closed classifier handling, buffered SSE verification,
and signed audit storage. The launcher requires externally provisioned identities
and secrets; it does not trust identity headers from clients.

See the [production runbook](docs/PRODUCTION.md) for immutable installation,
configuration, monitoring, service isolation, and deployment acceptance gates.
The local 7B model's performance and accuracy still need to meet the application's
requirements on its actual deployment hardware.

## Custom-provider TLS inspection

The optional TLS gateway decrypts explicitly scoped HTTPS connections from managed
clients that trust its interception CA, inspects custom JSON prompts and responses,
and tracks connection lifecycle, expiry, byte budgets, and tenant isolation.
It does not install trust or change routing automatically. See the
[TLS inspection guide](docs/TLS_INSPECTION.md) for configuration and protocol limits.

## Coverage and limitations

Detectors cover recognizable patterns for prompt injection, sensitive data,
unsafe output, tool abuse, RAG poisoning, supply-chain risks, resource exhaustion,
agent behavior, and infrastructure exposure. The
[threat matrix](docs/THREAT_COVERAGE.md) records priorities and residual work.

```sh
python -m firewall.coverage --self-test --json
```

Rule self-tests verify canonical fixtures. The test suite also checks encoded
and Unicode variants, benign controls, policy enforcement, and protocol handling.
Neither check measures exhaustive attack coverage.

Known role-spoofing and paraphrased-override regressions now have blocking tests.
A local 7B evaluation measures input detection separately from configured output
invariants and tool enforcement. See [evaluation findings](docs/EVALUATION.md)
for results and remaining detection gaps. The [extended evaluation](docs/ADVERSARIAL_EVALUATION.md)
documents adaptive attacks, stateful agent workflows, and operational limits. This repository does not claim
comprehensive protection or mission-critical certification.

## Repository layout

| Path | Purpose |
| --- | --- |
| `firewall/core/` | Events, provenance, policy, risk, behavior, audit, and gateway |
| `firewall/detectors/` | Detection rules and canonical regression fixtures |
| `firewall/enforcement/` | Tool permissions, egress checks, quotas, and validators |
| `firewall/mcp/` | Registry pinning and JSON-RPC inspection |
| `firewall/serve/` | HTTP proxy, streaming inspection, and state adapters |
| `firewall/ml/` | Optional text classifiers |
| `firewall/multimodal/` | Text extraction for downstream inspection |
| `firewall/tenant/` | Tenant policy and control-plane support |
| `tests/` | Runtime and protocol regression tests |
| `dataset/`, `eval/` | Corpus generation and offline evaluation tools |

## Corpus evaluation

Corpus generation is optional and can produce several gigabytes of data.
Generated files stay outside version control.

```sh
python -m dataset.build_corpus
python -m eval.security_benchmark --per-category 200 --benign-cap 5000
python -m pytest -q tests/test_dataset_and_regression.py
```

The smoke benchmark counts non-allow decisions as interventions. It does not
execute tools or prove that downstream enforcement is safe.

## Changes

See [CHANGELOG.md](CHANGELOG.md).
