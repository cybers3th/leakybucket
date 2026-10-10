# Deployment and security boundaries

Leakybucket inspects text, proposed tool calls, MCP JSON-RPC messages, and
retrieved content. Applications must place enforcement on every path before
executing tools or sending content downstream. The implementation is a
hardening foundation; deployment-specific authentication, authorization,
transport integration, load testing, and independent review are still required.

## Installation and verification

```sh
python -m pip install -e '.[test,serve]'
python -m firewall.coverage --self-test
python -m pytest tests/ --ignore=tests/test_dataset_and_regression.py -q
```

Run the complete test suite when the generated corpus is available. The dataset
integrity tests require `python -m dataset.build_corpus`; its default corpus is
large. CI deliberately runs the detector and enforcement tests without building
these artifacts.

Detector modules retain canonical positive and negative fixtures. Encoded and
Unicode variants are generated in the test suite rather than duplicated in
runtime source. These checks are authored regression cases, not independent
measurements of real-world detection accuracy.

## MCP integration

```python
from firewall.core.events import Actor
from firewall.mcp import MCPGateway, MCPServerDef, MCPServerRegistry

registry = MCPServerRegistry()
registry.register(MCPServerDef(
    server_id="knowledge", name="Reviewed knowledge server",
    allowed_capabilities=["tools", "resources"],
    allowed_hosts=["api.company.com"],
    allowed_resource_uris=["kb://public/*"],
    allow_sampling=False,
))
registry.pin_tool("knowledge", {
    "name": "search", "description": "Search public documents",
    "inputSchema": {
        "type": "object", "required": ["query"],
        "properties": {"query": {"type": "string", "maxLength": 1000}},
        "additionalProperties": False,
    },
}, risk_level="low")
firewall = MCPGateway(registry=registry, require_correlated_responses=True)
actor = Actor(user_id="verified-user", tenant="acme",
              session_id="server-issued-session", authenticated=True)
request = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
           "params": {"name": "search", "arguments": {"query": "release notes"}}}
firewall.gate_outbound("knowledge", actor, request)
# Only now send request through the MCP transport.
# Inspect the matching response with gate_inbound before delivering it.
```

Pin definitions only after review. Do not automatically pin freshly advertised
tools. Pins now retain the approved input schema and fingerprint the complete
definition, including annotations. Existing persisted pins without a stored
schema must be repinned from reviewed definitions before calls are accepted.
JSON Schema validation uses an empty reference registry; remote schema retrieval
is disabled. Administrator-reviewed schemas are configuration, not user input.

Enable response correlation in deployments using the same gateway for both
directions. It binds request IDs to tenant, user, session, and server, rejects
replays and unsolicited responses, and bounds pending requests. Inspection-only
consumers can leave it disabled, but then do not receive replay protection.
Approval callbacks must approve the exact operation being inspected. Pending
approval requests remain subject to content inspection and expiry; an inspected
request is not proof that the transport actually sent it.

Unknown servers, unpinned calls, unknown outbound methods, denied capabilities,
forbidden resource schemes, and unsafe URL destinations are withheld.
Server-initiated sampling requires explicit configuration. Other server-initiated
requests are denied; transports must handle safe protocol-level ping themselves.
Blocked content is never made safe merely by approving an earlier tool call.
MCP sanitization is withheld because this gateway does not produce verified
replacement JSON-RPC messages.

Message limits default to 1 MiB, depth 32, and 20,000 nodes. Transport adapters
must enforce byte limits **before** parsing JSON, reject duplicate object keys,
and reject JSON-RPC batches. Gateway limits protect inspection after decoding.

## Network and tool boundaries

Host allowlists and IP checks reject credentials in URLs, malformed ports,
ambiguous URLs, loopback/private IP literals, metadata hosts, and IPv4-mapped
IPv6 loopback addresses. Tools can be scoped to resource paths and agent IDs.
Authorization failures and paths outside the declared scope cannot be overridden
by a generic approval callback.

Text inspection does not stop DNS rebinding by itself. Before opening a socket,
call `EgressController.check_resolved(url, addresses)` on the actual DNS results.
Connect only to the validated addresses, preserve TLS hostname verification,
and repeat the checks at every redirect. Enforce equivalent restrictions at the
network/sandbox layer so a tool cannot create an uninspected connection.
The current default egress policy rejects private addresses. Deliberate internal
network integrations need a separately reviewed policy at the transport layer.

Inspect and enforce local tool results after execution. A blocked result raises
`ToolBlocked`; unexpected approval results raise `ApprovalRequired`. Sanitization
of tool arguments/results is withheld rather than executing/delivering the
original value. Tool execution still needs process isolation and filesystem
sandboxing; detections cannot undo a side effect that already happened.

## Proxy and streaming

The OpenAI-format proxy treats supplied `x-lb-*` headers as untrusted. Configure
`build_openai_app(actor_resolver=...)` with an authentication function that returns
a verified, authenticated `Actor`. The resolver may be asynchronous. In its
absence, requests use an anonymous actor; the app does not authenticate users.
Use an authenticated ingress and TLS, and prevent clients from bypassing it.
Transport OAuth must validate token issuer, audience, scope and expiry. This
message firewall is not an OAuth authorization server and does not implement
OAuth token validation or delegation.

The proxy inspects every returned choice and refuses outputs that require
review. Tool-call responses/streams require a separate enforced tool gateway;
the text proxy withholds them. Unreviewed input/output sanitization is also
withheld. Streaming uses `buffer_until_verified=True` by default so no partial
secret is released before inspection. This trades token-by-token delivery for
complete-response verification. Opting out restores live rolling-window delivery
and can release a prefix before a later chunk completes an attack.

Multimodal extraction modules exist, but the text proxy does not provide
end-to-end security for image/audio binary content. An integration must invoke
appropriate extraction and inspect the extracted text before delivery.

## Audit and operational state

Standard `AuditLog` retains at most 1,000 records in memory by default. On-disk
JSONL remains available when a path is configured. Arguments, detector evidence,
freeform descriptions, and sensitive decision details are omitted by default.
`include_sensitive_details=True` is an explicit opt-in for restricted diagnostics;
protect those files as sensitive data. The separate `SignedAuditLog` still has
its own retention and content behavior and must be reviewed before production
use; its existing SIEM sinks are not automatically covered by these defaults.

Tenant and user IDs are included in behavioral, rate-limit, MCP correlation and
MCP data-flow keys. Rate-limit keys and pending requests are bounded. MCP flow
tracking retains up to 500 fragments per session and refuses new sessions after
its configured capacity. Release finished sessions with
`gateway.data_flow.clear_session(actor)` and
`gateway.behavior.release_session(event)` where applicable. A rate limiter that
reaches its key capacity refuses new keys; lifecycle management is required.
Behavior tracking remains in memory and requires application-managed lifecycle.

Use one gateway per worker and preserve session affinity. In-memory lineage and
response correlation are not shared across workers. The repository's distributed
state adapters do not automatically make these components distributed. Distributed
permissions, quotas and lineage need explicit integration and verification.

## Limits of claims

Rules detect known attack shapes and policy violations; they are not a proof
against all prompt injection or a truth oracle. High-risk output rules identify
claims needing review; they do not establish whether a claim is factually false.
Coverage examples test authored patterns and representations. Validate with your
own traffic, adversarial prompts, tools, tenant roles and false-positive budget
before rollout. Start with shadow decisions and deploy enforced paths only after
reviewing the resulting decisions.

Primary references: [MCP authorization](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/docs/specification/2025-11-25/basic/authorization.mdx),
[MCP security guidance](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/docs/docs/2026-07-28/tutorials/security/security_best_practices.mdx),
and [JSON Schema reference handling](https://python-jsonschema.readthedocs.io/en/v4.25.0/referencing/).

## Semantic inspection and application output constraints

Semantic inspection is opt-in. Pass an injection classifier to `Gateway`; a
classifier implements `predict(text) -> (malicious: bool, score: float)`.
`LocalSemanticClassifier` can use an existing local model endpoint, and the
optional transformer classifier supports an independently deployed encoder.
No model is downloaded or contacted by a default `Gateway`.

```python
from firewall import Gateway
from firewall.enforcement.output_validators import OutputConstraints, CredentialAdviceValidator
from firewall.ml import LocalSemanticClassifier

classifier = LocalSemanticClassifier(local_model_endpoint, deployment_model_name)
gateway = Gateway(
    injection_classifier=classifier,
    output_constraints=OutputConstraints(
        forbidden_markers=application_markers,
        forbidden_literals=protected_literals,
        forbidden_action_prefixes=disallowed_action_prefixes,
    ),
    output_validators=(CredentialAdviceValidator(),),
)
```

The configuration above comes from the application, not a request, model output,
or retrieved document. Marker matching ignores case and punctuation; literal
matching covers bounded decoded views and whitespace splitting. Define these
constraints from actual application invariants rather than copying evaluation
markers into production. For structured output, `OutputConstraints(schema=...)`
uses offline JSON Schema validation and rejects unresolved remote references.

The baseline policy blocks positive semantic injection labels. Classifier errors,
invalid labels, and inspection-budget overruns block rather than silently skipping
inspection. Long carriers are inspected in overlapping windows; there is a finite
request budget. Semantic labels can still miss attacks or produce false positives.
The local generative classifier's binary score is not a calibrated probability.
It distinguishes user requests from instructions embedded in untrusted carriers;
tool permissions and destinations are enforced separately. Encoder adapters do
not silently truncate carriers; model-limit failures block inspection.

Custom `output_validators` receive the output event and must return exactly `True`
to accept it. Rejection or exceptions block delivery. `CredentialAdviceValidator`
is a narrow, optional check for clear affirmative advice to publish credentials;
it does not establish general factual or security correctness. Broader advice
safety requires independent domain validation.

Configured output constraints require buffered streaming verification. Schema
and callback validation run on the complete response, while literal/marker checks
can also stop the stream earlier. Tool results are checked for prohibited strings,
including structured keys and values, without applying the model's response
schema to individual tool results.

## Python tool schemas and execution boundaries

`ToolDefinition.input_schema` is an optional administrator-reviewed JSON Schema.
When supplied, arguments are validated before calling the function. Invalid
names, non-object arguments, callable-binding errors, role/agent violations, and
out-of-scope paths are denied before execution. Register explicit schemas when
value types, enums, or other argument semantics matter; Python argument binding
alone does not enforce type annotations.

Network-capable tools check URLs against the tool's host allowlist and private
address restrictions even without a global egress controller. An additional
global controller can impose stricter restrictions. Egress denials are critical
and cannot be overridden by an approval callback. Actual transports must still
bind to verified DNS results and recheck redirects, as documented above.

Shell substitutions are inspected in shell contexts. Markdown delimiters and
normal Python code fences no longer trigger the generic backtick rule. Dangerous
commands, secrets, unsafe templates, and executable downstream destinations remain
subject to inspection; callers must provide the actual downstream destination.
