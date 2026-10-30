# Custom-provider TLS inspection and connection tracking

This optional adapter is an **explicit HTTPS inspection proxy**, not a passive
packet sniffer or a Linux netfilter replacement. Managed clients connect through
it and trust its interception CA. It terminates client TLS and creates a separate,
certificate-verified TLS connection to the configured provider. A root certificate
alone cannot passively decrypt modern TLS sessions; the gateway needs its CA
private key and an inline proxy path.

The current profile supports custom JSON AI APIs on exact configured hostnames,
ports, and POST paths. It inspects all JSON keys/string values in both directions
and noncredential HTTP header values. It blocks unsupported content rather than
forwarding it without inspection. This does not automatically support every
custom AI protocol or browser application.

## Installation

TLS inspection requires Python 3.12 or newer. The optional runtime is mitmproxy;
the base firewall does not install it.

```sh
python -m eval.build_tls_dependency
python -m pip install --find-links .tls-dependencies '.[tls,serve]'
```

For a reviewed Linux CPython 3.14 deployment, use the hashed
`requirements/tls-py314.lock` and an approved wheel instead of an editable install.
First build the reviewed TLS dependency wheel, then install the hashed TLS lock.
The separate `requirements/production-py314.lock` does not include TLS interception.
Regenerate the TLS lock from the reviewed test environment with
`python -m eval.lock_runtime --extra tls --extra serve --wheel .tls-dependencies/mitmproxy-12.3.0+leakybucket.2-py3-none-any.whl --output requirements/tls-py314.lock --audit-output requirements/tls-audit-py314.lock`.

## Patched TLS dependency

The reviewed upstream mitmproxy 12.3.0 package limits Brotli to 1.2.0. The dependency
audit flags that decoder, while the fixed 1.2.1 violates the upstream package's
upper bound. The TLS extra therefore requires an explicit local build,
`mitmproxy==12.3.0+leakybucket.2`, with `Brotli>=1.2.1,<1.3` and `tornado>=6.6,<6.7`.
The upstream Tornado cap of 6.5.10 also excludes the 6.6 security fixes for
CVE-2026-116577, CVE-2026-115927 and CVE-2026-116578; see the
[upstream release](https://github.com/tornadoweb/tornado/releases/tag/v6.6.0).

`eval.build_tls_dependency` downloads an upstream wheel by a fixed SHA-256,
preserves all executable code and licenses, and changes only dependency metadata,
the local package version, and wheel RECORD hashes. It builds a reproducible,
uncompressed wheel in the ignored `.tls-dependencies/` directory. This is an
explicit downstream packaging patch, not an upstream release. The launcher refuses
the original dependency combination. There are no vulnerability suppressions.

The hashed TLS lock pins that local wheel and its actual runtime dependencies.
`requirements/tls-audit-py314.lock` is an **audit inventory only**, not an installer:
it scans mitmproxy's unchanged code using its upstream version and scans Brotli and Tornado at
their actual fixed versions. CI checks installation consistency with `pip check` and
runs the TLS tests. Retire this packaging patch when an upstream release accepts
the fixed dependency and passes the same checks. Distribute the approved dependency
wheel alongside the firewall wheel in your private artifact store; it is not
published to PyPI or embedded in the base firewall wheel.

## CA and explicit configuration

Generate an isolated interception CA in a **new directory**:

```sh
leakybucket-tls init-ca /private/path/leakybucket-ca
```

This prints the public certificate path. It does not install trust, configure
clients, or reroute traffic. Distribute only `mitmproxy-ca-cert.pem` to authorized
managed clients through your existing trust-management process. Keep
`mitmproxy-ca.pem`, which contains the private key, on the gateway with mode 0600
or stricter. Do not distribute the combined certificate/private-key bundle.
Rotate and revoke the interception CA through your organization's PKI process.

Create an operator-owned configuration outside the repository. Replace the
reserved example hostname and path with the actual custom provider's API:

```json
{
  "providers": [
    {"host": "ai.vendor.example", "paths": ["/generate"], "ports": [443]}
  ],
  "tenant": "company",
  "proxy_username": "managed-ai-service",
  "proxy_password_file": "/private/path/proxy-password",
  "ca_dir": "/private/path/leakybucket-ca",
  "audit_path": "/private/path/tls-audit.jsonl",
  "audit_key_file": "/private/path/audit-key",
  "rules_only": true
}
```

`rules_only: true` explicitly selects deterministic inspection. For semantic
inspection, remove it and supply:

```json
{
  "semantic": {
    "endpoint": "http://127.0.0.1:8001",
    "model": "your-deployed-classifier",
    "token_file": "/private/path/classifier-token"
  }
}
```

That object is a field in the same configuration, not a separate complete config.
The classifier must satisfy the deadline on the deployment hardware. Timeouts,
invalid labels, overload, and classifier outages withhold traffic.

`proxy_password_file` must contain a random ASCII password of at least 32
characters. `audit_key_file` must contain an externally managed HMAC key of at
least 32 bytes. Credentials and CA private keys must have private file modes.
Optional `protected_literals_file` supplies one application-protected literal per
line, and `upstream_ca_file` supplies an explicitly trusted private upstream CA.
Upstream certificate and hostname verification remain enabled.

```sh
leakybucket-tls run --config /private/path/tls-config.json
```

The launcher binds to loopback, default `127.0.0.1:8081`. Configure authorized
clients with this explicit proxy, proxy authentication, and the public CA trust.
Use an authenticated encrypted ingress for remote clients. Do not expose an
unauthenticated or plaintext-credential proxy on a network interface. Neither
credentials nor CA keys are placed in process arguments.

No provider hostname is implicitly trusted. Wildcards and unreviewed paths are
not accepted. Unknown domains, methods, paths, plaintext requests, and mismatched
CONNECT/SNI/HTTP authorities are rejected. A custom provider's nonstandard auth
or payload format must be reviewed before enabling it.

## Network and connection enforcement

The adapter checks DNS results before opening an upstream socket and connects
only to a validated numeric address while preserving the configured hostname for
SNI and certificate verification. Any private result rejects the connection,
including mixed public/private DNS responses. A provider may explicitly pin
`approved_ips`; then every DNS result must match that set. This is also the only
way to approve a private/internal provider address. Review those exceptions as
network permissions, especially loopback and metadata addresses.

ConnTracking records tenant, server-generated client connection ID, client peer,
approved target, lifecycle state, payload byte totals, and in-flight requests.
It stores no prompts, credentials, TLS keys, or packet bodies. Defaults are:

- 1,024 connections globally and 256 per tenant;
- 16 in-flight requests per connection and 128 inspected requests globally;
- 16 MiB cumulative JSON payload bytes per connection;
- 60-second idle expiry and one-hour maximum lifetime.

The TLS launcher applies a 30-second transport inactivity timeout. Unknown,
expired, blocked, duplicate, cross-tenant, and over-budget operations cannot
resume a previously allowed request. Connection targets cannot change midstream.
Disconnects and errors release request state. `ConnTracker.snapshot()` provides
bounded lifecycle counters; `lookup(tenant, connection_id)` returns a copy.
These counters describe application payloads, not TCP sequence numbers, kernel
SYN state, or encrypted on-wire byte counts. Kernel conntrack and network-wide
connection limits remain separate deployment controls.

## Inspection contract and limits

Requests and responses are buffered before forwarding. Limits are 256 KiB per
body, 50,000 extracted characters including inspected headers, bounded JSON depth
and node count, and bounded asynchronous inspection admission. Duplicate JSON
keys and non-finite JSON constants are rejected. Compression is refused to avoid
unbounded decompression and ambiguous inspection. Streaming JSON bodies are
buffered; SSE, WebSockets, generic TCP/UDP, binary bodies, redirects, and unreviewed
upstream errors are withheld. This version does not provide a generic SSE adapter.

Provider `Authorization`, cookies, and standard API-key headers are treated as
authentication material, not model prompts. Other request headers are inspected.
Response headers are inspected; `Set-Cookie` and `Alt-Svc` are stripped rather than
relayed. Proxy credentials never reach the provider. The configured API must not
interpret authentication headers as model instructions. Cookie-based login and
browser-session workflows are outside this JSON API profile.

Transport decryption does not decrypt application-encrypted JSON values or infer
semantics for arbitrary binary protocols. Multimodal media, opaque application
payloads, and provider-specific streaming need reviewed adapters. Prompt filtering does not authorize provider-side tools or undo remote side effects.
Those actions still need application-specific permissions and validation. The generic
profile can also flag legitimate system instructions or code; measure false
positives against actual provider traffic before enforcement.

Certificate-pinned applications can reject the interception certificate. There
is no pinning bypass or automatic uninspected fallback. HTTP/3 is disabled on this
proxy, but that does not block clients from using QUIC or direct sockets outside
it. An enterprise routing/egress policy must force the selected AI traffic through
the gateway and prevent alternate direct TCP/UDP paths. This code does not change
host routing, install a system CA, or configure transparent interception.

Signed auditing uses the existing bounded/redacted logger. The launcher disables
mitmproxy's traffic dumper and does not expose its web UI. Do not add raw flow
recording, insecure upstream verification, ignored hosts, or streaming passthrough
when deploying this enforcement profile. CA/key files and packet/flow dumps are
excluded from Git and distribution manifests.

## Verification

```sh
python -m pytest tests/test_conntrack.py tests/test_tls_inspection.py -q
```

The real TLS tests create private test CAs and a local HTTPS origin, trust the
interception CA only in a test client context, authenticate CONNECT, and verify
that blocked prompts never open an upstream connection. They also verify response
withholding, unknown-domain denial, untrusted-client CA failure, upstream hostname
verification, DNS pinning, authority checks, expiry, and tenant isolation. They do
not establish security for every third-party application or network topology.

Implementation references: [mitmproxy certificates](https://docs.mitmproxy.org/stable/concepts/certificates/),
[event hooks](https://docs.mitmproxy.org/stable/api/events.html), and
[buffering/streaming options](https://docs.mitmproxy.org/stable/concepts/options/).
