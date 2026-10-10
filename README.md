# LeakyBucket

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
