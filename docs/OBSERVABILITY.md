# Terminal operations — v1.1

The CLI operates the existing enforcing OpenAI-compatible Chat Completions
proxy. There is no browser interface or static asset server. Configure one provider per process: OpenAI or an Ollama server's `/v1`
endpoint. Anthropic's native Messages protocol is not implemented. The proxy
continues to reject tool calls, multimodal requests and unsupported carriers;
the timeline shows actual policy, provider and streaming spans. It never
fabricates tool or retry activity.

## Container startup

```sh
docker compose up --build -d
```

The image initializes a private service token and signed-audit key in its
persistent `/data` volume. Run terminal commands inside the container:

```sh
docker compose exec leakybucket leakybucket status --token-file /data/service-token
docker compose exec leakybucket leakybucket traces --token-file /data/service-token
docker compose exec leakybucket leakybucket watch --token-file /data/service-token
```

The credential grants access to its configured tenant's proxy and traces.
The Compose port binds to localhost. Remote use requires HTTPS and externally
provisioned credentials; see [PRODUCTION.md](PRODUCTION.md).

The default upstream is `https://api.openai.com/v1`. Before sending requests,
provision its API key without putting it in command history or the repository:

```sh
read -rs UPSTREAM_KEY
printf '%s' "$UPSTREAM_KEY" | docker compose exec -T leakybucket python -c 'import pathlib,sys; p=pathlib.Path("/data/upstream-token"); p.touch(mode=0o600); p.write_bytes(sys.stdin.buffer.read())'
unset UPSTREAM_KEY
docker compose restart leakybucket
```

The bootstrap launcher uses `/data/upstream-token` if present; it is distinct from
the client service token. Existing credentials are preserved across restarts.
Image build/download time varies; startup does not wait for a model download.
The service can start before provider credentials are configured, but model
calls will fail until the provider is available and authenticated.

Compose explicitly selects rules-only inspection by default. It does not run a
7B classifier. Use the semantic classifier and secret-file configuration in the
production runbook when deploying semantic inspection. Classifier HTTP endpoints
must remain loopback-local to the gateway's network namespace.

## Local startup from any directory

```sh
leakybucket start
leakybucket status
leakybucket traces
leakybucket trace
leakybucket policy validate
leakybucket watch
```

`start` initializes local credentials and starts a background process. `stop`
stops that process. `watch` stays open until Ctrl-C; run it last or in a separate
terminal. `trace` without an ID selects the latest request. `TRACE_ID` in examples
is a placeholder; use an actual ID from `traces` when selecting a particular request.
An empty trace list is normal until a request passes through this proxy.

Configuration lives in `~/.config/leakybucket/policy.yaml` and state in
`~/.local/state/leakybucket/` (tokens, signed audit, SQLite history, connection
settings, process lock and `service.log`). These follow `XDG_CONFIG_HOME` and
`XDG_STATE_HOME`; `LB_CONFIG_DIR` and `LB_STATE_DIR` override the complete paths.
All commands use these locations regardless of your current directory.

Local startup defaults to built-in inspection rules with no semantic classifier.
It prints the mode explicitly. The default upstream is
`http://127.0.0.1:11434/v1`; install and start your model provider separately.
Service readiness confirms inspection and storage, not provider availability.

Choose a different upstream or policy explicitly:

```sh
leakybucket stop
leakybucket start --upstream-url https://your-provider.example/v1 --policy /absolute/path/policy.yaml
```

The successful startup saves the upstream and policy paths for later restarts.
Explicit flags and the existing `LB_*` environment settings take precedence.
`policy validate` without a path validates the saved policy. The repository's
legacy `deploy/policy.yaml` path also resolves from an editable installation;
the command prints the actual file being validated.

For a provider API key, provision the private `upstream-token` file in the state
directory or set `LB_UPSTREAM_TOKEN_FILE`. This is distinct from `service-token`.
For managed deployments, use the production runbook's semantic classifier,
identity and secret-file settings.

`start --foreground` stays attached for containers and service managers;
stop it using Ctrl-C or the service manager. The Docker image uses this mode.
`--bootstrap-dir PATH` (also `--state-dir PATH`) overrides startup state. Use
matching `--state-dir` on terminal commands when managing that custom instance.
`govern` remains a command alias; stdin-based `leakybucket` inspection is preserved.
The strict environment-configured `leakybucket-serve` entry point still requires
explicitly provisioned settings and does not select local defaults.

## Storage and privacy

SQLite is the default (`LB_TRACE_DATABASE`, or `traces.sqlite3`). Bootstrap uses
its private state directory. SQLite uses WAL with full synchronous commits and
requires a private database file. Store the volume on durable local storage;
monitor disk consumption and back up the database with SQLite's backup API.
Trace history is retained until an operator removes it. This milestone does not
provide automatic retention or archival.

For PostgreSQL, install `.[observe,postgres]` and set `LB_TRACE_DATABASE` to a
`postgresql://...` DSN. Use a dedicated database role, TLS and a secret manager for
nonlocal deployments. Queries always scope to the tenant supplied by the trusted
authenticator. A single serialized connection has a five-second statement
limit; this is not an HA or connection-pool implementation.

By default, stored records include model, status, token counts, policy digest,
latency, cost estimate and spans, without prompt or response text. Set
`LB_CAPTURE_CONTENT=true` only when your data policy allows storing raw prompts
and delivered responses. Prompts can contain credentials and personal data.
Blocked upstream responses are never copied into trace content. Metadata,
including model and rule names, can still be sensitive. Protect database backups
and the service token. Trace storage is separate from the signed security audit.

A trace is committed before the response is released. Persistence failure
withholds the response and makes readiness fail; fix storage and restart the
service. The provider may already have processed the request. Do not blindly
retry billable or side-effecting operations. Client disconnects or process loss
can leave a request without a completed trace; this is not an exactly-once ledger.

## Provider diagnostics and guarded chat

`leakybucket doctor` distinguishes service readiness, policy validity and provider
availability. It reports whether the models endpoint is unreachable, requires
credentials, has no models, or uses an unsupported response. It only queries
`/models`; it does not generate billable completions or download weights. An HTTP
404 from `/models` indicates that discovery is unsupported or the base URL is
incorrect, not that the model was tested successfully. Discovery alone does not
prove that a chat request will succeed.

Use `doctor --json` for structured diagnostics. Exit status is 0 when the service,
policy and model discovery checks pass, 1 for incomplete readiness, and 2 for
invalid command arguments or configuration. HTTP redirects are rejected and
responses are bounded. Provider credentials are separate from service credentials
and are not included in the report.

```sh
leakybucket doctor
leakybucket chat --model YOUR_MODEL 'Explain why rain forms.'
printf '%s' 'Explain why rain forms.' | leakybucket chat --model YOUR_MODEL --json
```

Replace `YOUR_MODEL` with a model ID your provider offers. `chat` sends one textual
user message through the authenticated firewall, with input/output inspection
and trace storage. It does not call the provider directly. Prompts are bounded to
50,000 characters. Responses default to a 256-token cap; `--max-tokens` accepts
1–4096. Terminal control characters are escaped. Use `--json` to return
the inspected completion envelope and trace ID. A blocked request explains how to
inspect its trace; upstream failures direct you to `doctor`. Provider charges can
apply to chat requests.

`start` refuses changed provider or policy flags while an instance is already
running. Stop it first, then restart with the desired configuration. This avoids
silently appearing to apply settings to an existing process.

## Terminal commands

```sh
leakybucket status
leakybucket traces --model your-model --limit 20
leakybucket traces --since 1793318400 --min-cost 0.01 --json
leakybucket trace
leakybucket trace --json
leakybucket watch
leakybucket watch --count 10 --json
```

All four commands accept `--url`, `--token-file`, `--ca-file`, `--state-dir`, and `--json`.
Defaults are `LB_URL` (or `http://127.0.0.1:8080`), `LB_SERVICE_TOKEN_FILE`
(or the saved token in the persistent state directory), and `LB_CA_FILE` (or the system CA store).
Never put the service token in a command argument or URL. HTTPS is required
outside loopback. Redirects are rejected and environment proxy settings are
ignored so credentials are not forwarded to another destination.

`traces` lists summaries; `trace` shows spans and any explicitly captured content.
Human output escapes terminal control characters; `--json` emits escaped JSON
for scripts. `watch` prints completed requests as they arrive and stops on Ctrl-C.
It is a live view, not a durable subscription: use `traces` to recover history
following disconnection. Unknown usage and costs are displayed as `unknown`.

## Headless API

The CLI uses these authenticated endpoints; applications can also query them.

Send `Authorization: Bearer <service-token>`:

- `GET /api/traces?model=MODEL&since=UNIX_SECONDS&until=UNIX_SECONDS&min_cost=USD&limit=100&offset=0`
- `GET /api/traces/{id}` — full trace, including content if explicitly enabled.
- `GET /api/status` — policy/storage health and alert failure/drop counters.
- `GET /api/live` — WebSocket; send `{"token":"<service-token>"}` as its first
  message within five seconds. Events are `connected`, `started` and `completed`.

Trace listings contain metadata summaries; use the detail endpoint for spans
and content. Maximum page size is 200. Newest traces come first, with offset
pagination. `X-LeakyBucket-Trace` identifies a completed chat request. Failed
authentication, malformed JSON and requests rejected before trace admission do
not create records. Completed delivery status is an HTTP status, not a measure
of model quality or a detector verdict.

Live queues are bounded to 32 events per subscriber, 64 subscribers total.
Slow consumers can miss events; reconnect and query persisted history. Chat
admission is bounded at 32 and database jobs at 48; cancellation retains database
capacity until the worker exits. Trace body reads time out after ten seconds.
Spans retain at most 256 entries; a provider span includes the total chunk count
when chunk detail is truncated. The existing proxy buffers and inspects the
complete stream before delivering it, so chunk timings reflect provider arrival,
not progressive client delivery.

## Policy validation and reload

```yaml
version: 1
rules:
  - name: restricted-model
    model: internal-only
    action: block
  - name: sensitive-word-warning
    input_contains: confidential
    action: warn
pricing:
  your-model-name:
    input_per_million: 1.00
    output_per_million: 3.00
alerts:
  latency_ms: 5000
  cost_usd: 0.10
```

Prices above illustrate the schema; they are not provider price recommendations.
Use your contracted USD rates per million tokens. Costs use provider-reported
prompt/completion usage; missing usage or pricing stays unknown. Cached-token,
reasoning-token and provider billing adjustments are not modeled.

`model` is an exact match; `input_contains` is a case-insensitive literal match
across textual messages. Conditions in one rule are ANDed. `block` prevents
provider dispatch; `warn` records a matching span and continues through the
existing firewall. These policies can add restrictions but cannot override the
firewall. They are not a replacement for semantic inspection or tool authorization.

Validate with `leakybucket policy validate PATH`. The file is checked every
second and an entirely validated snapshot is swapped atomically. Invalid edits
keep the previous snapshot for diagnosis, fail readiness, and withhold new chat
requests until a valid file is restored. In-flight requests retain the snapshot
that admitted them. Duplicate keys, aliases, unsafe tags, unsupported fields,
nonfinite prices and oversized policies are rejected. Replace the file atomically
when possible. When using a file bind mount, edit its contents in place or mount
the containing directory so atomic replacements become visible in the container.

## Slack alerts

Set `LB_SLACK_WEBHOOK_FILE` to a private file containing a Slack incoming webhook
at `https://hooks.slack.com/services/...`. Mount it read-only in containers.
Thresholds apply per completed request, using strict greater-than comparisons.
Alerts include the trace ID, latency and estimated cost, without prompt/response
text, model names, tenant names or credentials.

Delivery is best effort through a bounded 32-item queue with a five-second HTTP
timeout, no redirects and no automatic retries. Full queues drop alerts and
increment `alert_drops`; HTTP/network failures increment `alert_failures`.
Pending alerts can be lost on shutdown. Durable delivery, cooldowns and grouping
are later milestones. No webhook is contacted unless configured.

## Verification

`tests/test_observe.py` exercises persistence, query injection and tenant
boundaries, authentication, the live stream, policy reload/failure, actual HTTP
upstream forwarding, content opt-in, blocked-prompt enforcement, storage failure
and cancellation capacity. Set `LB_TEST_POSTGRES_DSN` to run against a real
PostgreSQL database. CI also builds the container and audits the hashed Python
3.14 observability dependency lock. Container base images are pinned by digest;
update the digest and audit regularly.
