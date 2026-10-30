# Production deployment

Version 0.3.0 adds bounded serving, authenticated identities, deadline enforcement,
and durable signed auditing. These controls do not certify model accuracy or
replace tool isolation. Rollout approval depends on the application's actual
models, hardware, permissions, traffic, and acceptance thresholds.

## Install an immutable artifact

The hashed dependency lock targets CPython 3.14. Other supported Python versions
remain covered by the package's CI matrix, but need their own reviewed locks.
Build wheels in CI, retain their checksums, and install the approved wheel into a
fresh virtual environment. Do not deploy from an editable checkout.

```sh
python3.14 -m venv /opt/leakybucket/venv
/opt/leakybucket/venv/bin/python -m pip install --require-hashes -r requirements/production-py314.lock
/opt/leakybucket/venv/bin/python -m pip install --no-deps /path/to/approved/leakybucket_firewall-0.3.0-py3-none-any.whl
```

Use a dedicated unprivileged account. Keep credentials out of Git, command-line
arguments, URLs, and access logs. Provision secret files through your secret
manager with permissions restricted to the service account.

## Serving configuration

`python -m firewall.serve` or `leakybucket-serve` reads administrator-provisioned
environment settings. It fails startup when required settings are missing.

| Variable | Meaning |
| --- | --- |
| `LB_SERVICE_TOKEN_FILE` | File containing a random bearer credential, at least 32 ASCII characters |
| `LB_USER`, `LB_TENANT` | Verified service identity and tenant |
| `LB_SESSION_ID` | Server-controlled session ID for this service identity |
| `LB_UPSTREAM_URL` | Configured upstream API base URL, including `/v1` where required |
| `LB_UPSTREAM_TOKEN_FILE` | Optional upstream bearer credential; never the firewall service token |
| `LB_AUDIT_PATH` | Dedicated signed JSONL audit file |
| `LB_AUDIT_KEY_FILE` | Externally managed HMAC key file, at least 32 bytes |
| `LB_CLASSIFIER_URL`, `LB_CLASSIFIER_MODEL` | Local semantic classifier endpoint and deployed model name |
| `LB_CLASSIFIER_TOKEN_FILE` | Required model-service bearer credential when semantic inspection is enabled |
| `LB_ALLOW_RULES_ONLY=true` | Explicitly select rules-only inspection instead of semantic inspection |
| `LB_PROTECTED_LITERALS_FILE` | Optional UTF-8 file containing one application-protected literal per line |
| `LB_INSPECTION_TIMEOUT_SECONDS` | Inspection deadline, default 10 seconds |
| `LB_BIND`, `LB_PORT` | Listen address and port, defaults `127.0.0.1:8080` |

The bundled resolver is for service-to-service credentials. A service token maps
to one configured identity and session. It is not end-user OAuth, and it must not
be distributed to browser clients. Applications needing separate end-user roles,
sessions, or tenant identities must provide a reviewed `actor_resolver` to
`build_openai_app`. Cookie-based resolvers also require application CSRF controls.
Rotate credentials externally; restart or replace the resolver after rotation.

The proxy ignores `x-lb-*` identity claims. It requires authenticated actors with
nonempty user, tenant, and session IDs. Anonymous mode is an explicit Python API
opt-in intended for restricted local integrations. Client authorization headers
are never forwarded upstream by the app factory. Supply upstream authorization
separately. Remote upstreams require HTTPS; HTTP is permitted only for loopback.

Terminate TLS at a trusted ingress, prevent direct public access to the bind
address, and impose independent connection, body-read, and per-principal limits.
The service exposes `GET /health/ready`, which reports local admission capacity,
not model quality, classifier availability, or external dependency health.

`deploy/leakybucket.service` is a Linux systemd unit for `/opt/leakybucket`, with
credentials/configuration under `/etc/leakybucket` and writable audit state under
`/var/lib/leakybucket`. Provision the account, directories, artifact, dependency
lock, secret files, and `/etc/leakybucket/service.env` before enabling it. The
memory limit covers the firewall process; run inference in a separate service.
One process must own each audit file. Network filesystems and cross-host locks
are not supported by this local file-lock mechanism.

## Deadlines and admission

The HTTP request budget defaults to 60 seconds, including authentication, body
reading, inspection, upstream generation, and output verification. The default
limits are 32 simultaneous HTTP requests, a 256 KiB body, 128 text messages,
50,000 message characters, and four nonstreaming choices. Per verified user and
tenant, the default request quota is 120/minute with a burst of 30. The Python app
factory exposes these settings for an application's reviewed capacity plan.

`AsyncGateway` admits at most 16 inspections, including queued and running work.
It uses one worker by default and serializes access to shared gateway state even
when more workers are configured. Queue waiting counts against the inspection
deadline. Full admission returns 503; deadline expiry returns 504. Neither result
permits downstream dispatch. Per-principal quota exhaustion returns 429.

Python cannot forcibly terminate a running thread. Caller timeout or cancellation
therefore retains its admission slot until the worker actually exits. Expired
queued work cannot execute a tool. A tool already executing may finish its side
effect after cancellation: use a separately supervised process/container and
idempotency controls for consequential tools. Application callbacks and custom
classifiers must honor deadlines; hard CPU isolation requires process boundaries.

Synchronous input and output methods also check deadlines cooperatively and
return BLOCK on expiry. Regex/native code or callbacks can delay a cooperative
check; the threaded wrapper is not an operating-system CPU watchdog.

The local semantic adapter allows one model request at a time by default, uses a
5-second transport timeout, and shares a 10-second event budget across carriers.
Three consecutive failures open its circuit for 30 seconds. After that interval,
one probe tests recovery. Busy, failed, malformed, and open-circuit classifiers
all withhold affected requests. No failure silently switches to rules-only mode.
Deploy a classifier that meets the budget on the intended hardware. The previous
CPU 7B measurements exceeded it; bounding failure does not make that model fast.

`AsyncGateway.snapshot()` exposes bounded counters and the last 1,024 caller
latencies, with p50/p95 estimates. Export these through your authenticated
monitoring integration. Track allowed throughput separately from denials,
timeouts, quota failures, and admission failures. Do not blindly retry 503/504:
use a bounded retry budget and backoff outside consequential tool execution.

## Supported transport contract

This is a text Chat Completions proxy. It rejects multimodal messages, tool and
function calls, arbitrary message fields, logprobs, provider-specific content,
and request-supplied structured schemas. Agent tool calls must go through the
separate tool/MCP enforcement APIs. Unsupported features fail closed rather than
being relayed without inspection. Review this compatibility boundary before
routing an existing SDK application's traffic to it.

SSE responses are buffered, parsed across arbitrary transport chunk boundaries,
verified for complete framing and a finish marker, and inspected before release.
Limits are 1 MiB, 4,096 data events, 64 KiB per line, and 200,000 content characters.
Comments and opaque provider metadata are not forwarded. Responses use generated
IDs and the requested model label. Only a minimal numeric usage schema is
supported. Token-by-token latency is intentionally traded for full-response
withholding. Errors return controlled JSON; upstream bytes and traces are not
included. Responses use `Cache-Control: no-store`.

JSON rejects duplicate keys and non-finite constants. Upstream connections are
pooled, bounded, timed out, and closed during app cleanup. Redirects are disabled
so credentials cannot be forwarded to another origin by a redirect response.

## Audit and state lifecycle

The standard launcher requires signed audit storage. Audit records omit raw
content, arguments, freeform evidence, and actor metadata by default. HMAC keys
must persist outside the process. Each record is flushed and fsynced before a
successful write returns. Append errors make the signed logger unhealthy and
subsequent inspection cannot succeed through that logger.

Startup verifies the existing chain and signatures. Wrong keys, malformed tails,
and tampering prevent startup. It refuses a second local writer to the same file.
In-memory retention is bounded to 1,000 records; persistent sequence numbers
continue after restart. In-memory verification covers the retained window, while
startup verification covers the persisted file. Hash chaining cannot establish
whether a valid suffix was deleted: retain signed checkpoints externally when
truncation detection is required. Key rotation requires a new audit file and an
externally recorded checkpoint; mixed-key verification is not implemented.

The optional SIEM queue is bounded. Queue exhaustion, synchronous delivery
failure, and observed asynchronous shipping failure are explicit unhealthy
states. Asynchronous delivery is not a durable queue or an exactly-once service.
Use the local signed file as the primary record and an external durable shipper
for stronger delivery guarantees. Provision disk monitoring and an audited log
rotation procedure; this file writer does not manage disk retention for you.

Behavior history admits at most 10,000 sessions without evicting active security
history. Release completed sessions explicitly. The rate limiter, behavior
history, MCP correlation, and data-flow state remain local to a process. Preserve
session affinity. Replica failover does not preserve in-memory security quotas or
lineage; multi-worker/distributed operation needs a reviewed shared-state design.

## Verification and rollout gates

```sh
python -m firewall.coverage --self-test
python -m pytest tests/ --ignore=tests/test_dataset_and_regression.py -q
python -m eval.serving_load --output /private/path/serving-load.json
python -m pip_audit -r requirements/production-py314.lock --disable-pip --no-deps
```

The HTTP load harness uses synthetic upstream and classifier fixtures. It measures
serving behavior, not 7B inference performance or real-world attack resistance.
Use `eval.operational`, `eval.agent_workflow`, and `eval.adaptive_security` for the
separate model evaluations. Keep generated transcripts and credentials outside
the repository. Freeze final adaptive proposals before scoring, record the
runtime hash, and reject an attacker-quality conclusion when the unprotected
baseline never succeeds or when classifier failures dominate.

Before an enforced rollout, set numerical acceptance thresholds for latency,
allowed-request throughput, false positives, availability, memory, and the
application's forbidden actions. Exercise the actual deployment model and
permissions, tenant separation, timeout recovery, audit failures, restart, and
rollback. Commission independent adversarial review for sensitive or consequential
workflows. Existing unit tests and local fixture load tests do not satisfy those
application-specific acceptance gates by themselves.
