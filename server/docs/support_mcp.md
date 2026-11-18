# Read-only MCP Support Access and Operational Diagnostics

Nauthilus can expose its read-only support operations to MCP clients such as Codex and Claude Code. The MCP endpoint is
optional, off by default, and authenticated with OAuth 2.1 against Nauthilus itself as the issuer. It reuses the
historical authentication diagnosis (`server/supporthistory`, see [support_authentication_history.md](support_authentication_history.md))
and adds operational diagnostics (`server/supportops`), which management HTTP offers as well.

Nothing reachable through MCP changes state: there is no login test, unlock, flush, configuration change, or free
query (shell, SQL, Redis, log, or monitoring).

## 1. Architecture

| Layer | Package | Responsibility |
|---|---|---|
| Operation table | `server/supportapi` | The four operations, strict argument decoding, rendered result and error bytes, input schemas derived from the management OpenAPI document. Both transports use it, so they cannot drift apart. |
| Services | `server/supporthistory`, `server/supportops` | Authorization from verified scopes, validation, limits, concurrency gates, interpretation, coverage, audit. One process-owned instance each, shared by HTTP and MCP. |
| Shared primitives | `server/supportaccess` | Verified credential and principal identity, concurrency gate, stable error type, audit entry, text sanitizer. |
| HTTP adapter | `server/handler/support` | `POST /api/v1/support/...` with backchannel service tokens. |
| MCP adapter | `server/mcpserver` | Own listener, transport guards, bearer verification, RFC 9728 metadata, tools, limits, transport audit, metric. Official Go SDK (`github.com/modelcontextprotocol/go-sdk` v1.8.0), stateless Streamable HTTP with JSON responses. |
| Issuer | `server/idp`, `server/handler/frontend/idp` | Hosted resources, static-client admission, user right, login age, token lifetime cap, RFC 8414 metadata, RFC 9207 `iss`. |

| Tool (MCP) | HTTP route | Scope (any of) |
|---|---|---|
| `authentication_attempts_search` | `POST /api/v1/support/authentication-attempts/search` | `nauthilus:history_read`, `nauthilus:history_detail` |
| `authentication_attempt_detail` | `POST /api/v1/support/authentication-attempts/detail` | `nauthilus:history_read`, `nauthilus:history_detail` |
| `bruteforce_history` | `POST /api/v1/support/bruteforce-bans/search` | `nauthilus:history_read`, `nauthilus:history_detail` |
| `operational_diagnostics` | `POST /api/v1/support/operations/diagnostics` | `nauthilus:operations_read` |

`authentication_attempts_search` takes the same optional `response_mode` (`detailed`, `compact`) and
`include_ban_context` arguments as the HTTP route; the tool input schema is generated from the same OpenAPI component,
and the answers are byte-identical. The mode only selects the presentation and never widens the projection
([support_authentication_history.md](support_authentication_history.md), section 8.1).

Every tool is listed to every authenticated caller. Each call is authorized by the service from the verified scopes;
an MCP request for a tool whose scopes the token lacks is answered with `403` and an `insufficient_scope` challenge
before it reaches the SDK.

Supported MCP protocol versions: `2026-07-28` (stateless), `2025-11-25`, and `2025-06-18`. Older versions are refused.

## 2. Access model

Nauthilus is the authorization server and the resource server. The MCP endpoint is a *hosted resource*
(`identity.oidc.hosted_resources`), identified by its URL, which is also the RFC 8707 resource indicator and the token
audience.

- **Only pre-registered static clients.** A hosted resource admits only the clients in `static_clients`. A listed
  client must be public or set `require_pkce`, use `authorization_code` (optionally with `refresh_token`) only, and
  require MFA. Device flow and client credentials are never admitted, and the device endpoint never grants a hosted
  resource.
- **Dynamic client registration grants nothing.** A dynamically registered client is never admitted, whatever it
  declared. The support scopes are not part of the `mail-client-v1` profile, so such a registration is refused, and an
  authorization request that names the resource is answered with `invalid_target`. DCR is deliberately unsupported
  for MCP: both Codex and Claude Code register a new client after every failed authorization, so approving a single
  registration cannot work, and consent-based admission was rejected by the maintainer.
- **User right on directory data.** At authorization the issuer resolves the user's groups (`user_right.from: groups`
  or `group_dns`) in the same fresh backend lookup that builds the token claims and requires one of `any_of`; otherwise
  the client receives `access_denied`. A token claim never decides it.
- **Login age.** An authorization request for a hosted resource forces a new login (including MFA) when the browser
  session's login is older than `max_authentication_age` (`prompt=none` gets `login_required`). Code exchange and
  refresh are refused with `invalid_grant` after that age, so a removed group membership ends access at the latest then.
- **Exclusive grant.** A hosted resource is never combined with another resource in one grant (`invalid_target`), so
  its tokens cannot be replayed at another resource server.
- **Short tokens.** Access tokens for a hosted resource never live longer than `max_access_token_lifetime`
  (default 15 minutes).

### Token acceptance (every MCP request)

The endpoint accepts a bearer token only if all of the following hold; otherwise it answers `401` with
`error="invalid_token"` (no reason is published) or `503` when the token state cannot be read:

1. It is a current user access token of the configured issuer (JWT or opaque; `token_type=access_token`, an
   authorized party and a subject, no service-token `client_id` claim, an expiry in the future, the exact issuer for
   JWTs). ID tokens and service tokens are refused.
2. Its audience is exactly the issuing client plus this resource.
3. The issuing client is admitted by the hosted resource *now*: removing a client from `static_clients` rejects its
   existing tokens immediately and stops its refresh.
4. It carries at least one scope of the resource (otherwise `403 insufficient_scope`).

Every challenge names the protected resource metadata and the resource scopes:

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer resource_metadata="https://login.example.org/.well-known/oauth-protected-resource/mcp", error="invalid_token", scope="nauthilus:history_read nauthilus:history_detail nauthilus:operations_read"
```

### Discovery

| Document | Location |
|---|---|
| RFC 9728 protected resource metadata | `<resource origin>/.well-known/oauth-protected-resource<resource path>` and `/.well-known/oauth-protected-resource` |
| RFC 8414 authorization server metadata | `/.well-known/oauth-authorization-server` and, for an issuer with a path, `/.well-known/oauth-authorization-server/<issuer path>` |
| OIDC discovery | `/.well-known/openid-configuration` (same document as RFC 8414) |

Authorization responses (codes and errors) carry the RFC 9207 `iss` parameter, advertised as
`authorization_response_iss_parameter_supported: true`.

```json
{
  "resource": "https://login.example.org/mcp",
  "authorization_servers": ["https://login.example.org"],
  "scopes_supported": ["nauthilus:history_read", "nauthilus:history_detail", "nauthilus:operations_read"],
  "bearer_methods_supported": ["header"],
  "resource_name": "Nauthilus support diagnostics (read-only)"
}
```

## 3. Transport, limits, and audit

The MCP listener is plain HTTP on its own address (default `127.0.0.1:9097`) behind a TLS-terminating reverse proxy
(`tls_termination: trusted_reverse_proxy`). It serves only the resource path and the protected resource metadata.

- **TLS and proxy:** a request must come from a `trusted_proxies` address with `X-Forwarded-Proto` equal to the
  resource scheme. Only a plain-HTTP loopback resource may be reached directly from loopback (local testing).
- **Host:** the `Host` (or the proxy's `X-Forwarded-Host`) must be in `allowed_hosts` (default: the resource host).
- **Origin:** a request with an `Origin` header outside `allowed_browser_origins`, or with more than one `Origin`
  header, is refused. No CORS headers are sent; browser clients are not supported.
- **Client IP:** the right-most `X-Forwarded-For` hop that is not a trusted proxy (`ip` or `ip:port`); client-supplied
  hops left of it never decide it. A request from a trusted proxy without such a hop is refused, so clients never
  collapse into the proxy's address. A local setup that reaches a plain-HTTP loopback resource directly must
  therefore not list the loopback address in `trusted_proxies`.
- **Body inspection:** at most `max_request_bytes`; duplicate JSON member names, case variants of the JSON-RPC member
  names the SDK reads, JSON-RPC batches, and `Mcp-Method`/`Mcp-Name` headers that disagree with the body are refused.
  Operation arguments are decoded with the same strict rules on HTTP and MCP (unknown fields and duplicate names are
  `INVALID_REQUEST`).
- **Limits:** `timeout` per call, `max_concurrent` and `max_concurrent_per_principal` in-flight requests (`429`),
  `max_response_bytes` per tool result counting the structured content and its text copy (larger results become
  `RESPONSE_TOO_LARGE`), and `failed_auth_per_minute` failed bearer attempts per client (IPv4 address or IPv6 /64;
  `429`; a missing token is a discovery probe and is not counted). When the failure table is full, new clients are not
  tracked rather than refused, so a flood of rotating addresses cannot lock out valid tokens; above 10,000 distinct
  clients per minute, new clients are therefore not rate-limited. The services keep their own gates and bounds (history: 31-day window;
  diagnostics: 24-hour window).
- **Audit:** each service writes its own record (`audit=support_history`, `audit=support_operations`) with operation,
  principal (`<client>#<subject>` for user tokens), method, result code, result count, duration, and the bounded
  `audit_reference`. The endpoint writes `audit=support_mcp` records for refusals and tool calls (result, status,
  client IP, principal, tool, code). Tokens, arguments, results, and secrets are never logged.
- **Metric:** `mcp_requests_total{result}` with `ok`, `tool_error`, `unauthorized`, `forbidden`, `rejected`,
  `rate_limited`, `busy`, `error`.

### What leaves the host

Answers contain recorded or observed data: logins and accounts of the named subject, client IPs, protocols, client
ids, internal instance names, LDAP pool and target names, Redis pool names, and Loki and Prometheus instance labels. Recorded free
text is cleaned (control, format, and bidirectional characters replaced) and bounded; Loki and Prometheus instance labels outside a
plain pattern are replaced by a digest. The tool descriptions and the server instructions tell the model to treat
every string as untrusted data; this does not make natural-language content harmless, so operators should not expose
the endpoint to clients they do not trust.

## 4. Configuration

A complete example that passes the production config check is in
[examples/support_mcp.yml](examples/support_mcp.yml). The relevant blocks:

```yaml
runtime:
  servers:
    mcp:
      enabled: true
      address: "127.0.0.1:9097"
      hosted_resource: support-mcp
      tls_termination: trusted_reverse_proxy
      trusted_proxies: ["127.0.0.1/32"]
      allowed_hosts: ["login.example.org"]
      limits: {timeout: 15s, max_concurrent: 8, max_concurrent_per_principal: 2,
               max_request_bytes: 65536, max_response_bytes: 1048576, failed_auth_per_minute: 30}
      audit: {enabled: true}

identity:
  oidc:
    clients:
      - client_id: support-cli
        token_endpoint_auth_method: none
        require_pkce: true
        redirect_uris: ["http://127.0.0.1/callback", "http://localhost/callback"]
        grant_types: [authorization_code, refresh_token]
        require_mfa: [totp, webauthn]
        scopes: [openid, offline_access, nauthilus:history_read, nauthilus:history_detail, nauthilus:operations_read]
    hosted_resources:
      - name: support-mcp
        resource: "https://login.example.org/mcp"
        scopes: [nauthilus:history_read, nauthilus:history_detail, nauthilus:operations_read]
        user_right: {from: groups, any_of: [nauthilus-support]}
        max_authentication_age: 12h
        max_access_token_lifetime: 15m
        static_clients: [support-cli]

observability:
  diagnostics:
    operations:
      enabled: true
      sources:
        nauthilus_runtime: {enabled: true}
        loki:
          enabled: true
          url: "https://loki.example.org"
          tenant: "mail-prod"
          selector: {app: nauthilus, namespace: mail}
          instance_label: pod
          query_profile: nauthilus_diagnostics
          bearer_token: "${LOKI_READ_TOKEN}"
        prometheus:
          enabled: true
          url: "https://prometheus.example.org"
          selector: {job: nauthilus}
          instance_label: instance
          query_profile: nauthilus_diagnostics
          bearer_token: "${PROMETHEUS_READ_TOKEN}"
```

Validation at load rejects, among others: unknown keys (for example a `dynamic_clients` block), a hosted resource
that is not HTTPS (plain HTTP only for loopback), owned by a client, or reserved; scopes outside the support scopes;
a user right other than `groups`/`group_dns`; static clients that are missing, dynamic, confidential without PKCE,
allowed other grants, or require no MFA; an HTTPS resource without trusted proxies; Loki and Prometheus URLs with
query or user info, selectors or tenants with unsafe characters, more than one credential per source, a query profile
other than `nauthilus_diagnostics`, and limits above their ceilings.

**Reload behaviour.** The MCP listener and the diagnostics sources are built when the HTTP servers start, from the
same configuration snapshot as the IdP handlers; on stop, in-flight tool calls drain (at most 5 seconds) before the
listener reports done; a restart (or an operation that restarts the HTTP servers) applies
listener, transport, limit, and source changes. Hosted resources, static clients, and scopes are read through the
issuer on every request of that snapshot. Changing a hosted resource URL requires a restart; until then the endpoint
answers `503`.

### Reverse proxy (nginx)

```nginx
location = /mcp {
    proxy_pass http://127.0.0.1:9097;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_buffering off;
}
location /.well-known/oauth-protected-resource {
    proxy_pass http://127.0.0.1:9097;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

## 5. Client setup

Register one public static client (above) with both loopback redirect URIs; static loopback redirects match on any
port. Users must be members of a group in `user_right.any_of` and complete MFA.

**Codex** (`~/.codex/config.toml`, or `codex mcp add`):

```bash
codex mcp add nauthilus --url https://login.example.org/mcp --oauth-client-id support-cli
```

```toml
[mcp_servers.nauthilus]
url = "https://login.example.org/mcp"

[mcp_servers.nauthilus.oauth]
client_id = "support-cli"
```

**Claude Code:**

```bash
claude mcp add --transport http nauthilus https://login.example.org/mcp --client-id support-cli
```

Both clients discover the issuer through the protected resource metadata and RFC 8414, use PKCE S256 and the
`resource` parameter, and verify the `iss` parameter of the callback. Without `--oauth-client-id` / `--client-id` they
fall back to dynamic registration, which Nauthilus refuses for this resource.

## 6. Requests and responses

### MCP (JSON-RPC, `2025-06-18`)

```http
POST /mcp HTTP/1.1
Host: login.example.org
Authorization: Bearer <access token>
Content-Type: application/json
Accept: application/json, text/event-stream
MCP-Protocol-Version: 2025-06-18

{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"operational_diagnostics",
 "arguments":{"schema_version":"1","components":["ldap","redis"],"audit_reference":"INC-4711"}}}
```

The result carries the same JSON twice: as `structuredContent` and as the text content. A service error is a tool
result with `isError: true` and the same envelope the HTTP route returns:

```json
{"jsonrpc":"2.0","id":4,"result":{"isError":true,
 "content":[{"type":"text","text":"{\"error\":{\"code\":\"HISTORY_NOT_CONFIGURED\",\"message\":\"No history source is configured on this instance.\"},\"schema_version\":\"1\"}"}],
 "structuredContent":{"error":{"code":"HISTORY_NOT_CONFIGURED","message":"No history source is configured on this instance."},"schema_version":"1"}}}
```

### HTTP (service token with `nauthilus:operations_read`)

```http
POST /api/v1/support/operations/diagnostics HTTP/1.1
Authorization: Bearer <backchannel service token>
Content-Type: application/json

{"schema_version":"1","window":{"from":"2026-11-18T06:00:00Z","until":"2026-11-18T07:00:00Z"},"components":["ldap"]}
```

```json
{
  "schema_version": "1",
  "scope": {"window": {"from": "2026-11-18T06:00:00Z", "until": "2026-11-18T07:00:00Z"},
            "queried_at": "2026-11-18T07:00:04Z", "deployment": "prod", "instance": "mx-1"},
  "sources": [
    {"name": "nauthilus_runtime", "kind": "local_current", "status": "ok", "truncated": false,
     "coverage": {"from": "2026-11-18T07:00:04Z", "until": "2026-11-18T07:00:04Z", "instances": ["mx-1"], "view": "local_instance"}},
    {"name": "loki", "kind": "historical", "status": "partial", "code": "LOKI_RESULT_TRUNCATED", "truncated": true,
     "coverage": {"from": "2026-11-18T06:00:00Z", "until": "2026-11-18T07:00:00Z", "instances": ["mx-1", "mx-2"], "view": "log_labels"}}
  ],
  "findings": [
    {"id": "F1", "component": "ldap", "source": "nauthilus_runtime", "status": "failing",
     "scope": {"kind": "instance", "instance": "mx-1"}, "labels": {"pool": "auth", "target": "ldap://dc1.example.org"},
     "observed": {"at": "2026-11-18T07:00:04Z"},
     "freshness": {"observed_at": "2026-11-18T07:00:04Z", "basis": "current_state", "age_seconds": 0},
     "symptoms": [{"code": "LDAP_TARGET_UNHEALTHY", "count": 1}, {"code": "LDAP_BREAKER_OPEN", "count": 1}]},
    {"id": "F2", "component": "ldap", "source": "loki", "status": "observed",
     "scope": {"kind": "instance", "instance": "mx-1"},
     "observed": {"from": "2026-11-18T06:00:00Z", "until": "2026-11-18T07:00:00Z"},
     "freshness": {"observed_at": "2026-11-18T07:00:04Z", "basis": "log_window", "age_seconds": 4},
     "symptoms": [{"code": "LDAP_CONNECTION_ERROR", "count": 37}]}
  ],
  "hypotheses": [
    {"code": "DIRECTORY_UNREACHABLE_OR_OVERLOADED", "confidence": "medium", "finding_ids": ["F1", "F2"],
     "basis": "LDAP target health, breaker state, or LDAP connection errors",
     "caveats": ["CORRELATION_IS_NOT_CAUSATION", "LOCAL_INSTANCE_ONLY", "LOG_EVIDENCE_IS_NOT_CURRENT_STATE"]}
  ],
  "notes": ["VALUES_ARE_UNTRUSTED_DATA", "LOCAL_VIEW_NOT_CLUSTER", "RUNTIME_COUNTERS_ARE_PROCESS_LIFETIME",
            "HISTORICAL_SOURCE_INCOMPLETE", "HYPOTHESES_ARE_NOT_FINDINGS"]
}
```

Diagnostics error codes: `INVALID_REQUEST`, `WINDOW_TOO_LARGE` (`400`), `FORBIDDEN` (`403`), `OPERATIONS_BUSY`
(`429`), `OPERATIONS_NOT_CONFIGURED` (`503`), `INTERNAL_ERROR` (`500`); MCP adds `RESPONSE_TOO_LARGE`. The history
operations keep their contract unchanged.

## 7. Operational diagnostics

A request names an optional window (default: the last 15 minutes, at most 24 hours, not in the future), optional
components (`ldap`, `auth_backend`, `backend_monitoring`, `redis`, `clickhouse_export`, `auth_event_delivery`,
`policy`), and optional sources (`nauthilus_runtime`, `loki`, `prometheus`).

**Rules.** Missing data is `unknown`, never `ok`. Runtime findings describe this instance now (`current_state` for
gauges; `process_lifetime_counter` with `counting_since` for counters, which never claim anything about the window).
Log findings count lines inside the covered window (`log_window`); Prometheus findings count the increase of fixed
counters inside it (`metric_window`). `not_observed` requires proven coverage. Findings
of different sources are never merged; hypotheses relate them, are listed separately, reach at most `medium`
confidence (only when current state and log evidence agree), and always carry caveats. A failing or truncated source
never fails the call; its report says `partial`, `timeout`, `unavailable`, `not_configured`, or `not_requested`.

### `nauthilus_runtime` (instance-local, side-effect free)

Reads the in-process Prometheus registry; it never dials a backend and does not use `/healthz`.

| Component | Evidence | Status |
|---|---|---|
| `ldap` | `ldap_target_health{pool,target}`, `ldap_breaker_state{pool,target}`; `ldap_errors_total` per pool, operation, and result code | failing / degraded / ok; observed / not_observed |
| `backend_monitoring` | `backend_servers_status{server_status=wanted|alive}` | failing (none alive) / degraded / ok |
| `redis` | `redis_connection_timeouts_total` per pool | observed / not_observed |
| `clickhouse_export` | `nauthilus_plugin_*clickhouse*_flush_batches_total{result}`, `..._queued_rows_total{result}` | observed / not_observed |
| `auth_event_delivery` | `plugin_auth_events_total{outcome="dropped"}` per lane | observed / not_observed |
| `policy` | `policy_check_technical_errors_total` | observed / not_observed |
| `auth_backend` | `plugin_calls_total{extension_point="backend"}` with result `error`, `panic`, or `timeout` per module and component; `lua_vm_replaced_total` of Lua backend VM pools (`backend:<name>`); `auth_application_errors_total` per transport | observed / not_observed |

**LDAP error classification.** `ldap_errors_total` counts every failed directory operation, including the directory's
answer to a wrong user password (`op="bind"`, result code `49`). That answer is an outcome about the client, not a
fault of the directory, so it is reported as the informational symptom `LDAP_BIND_REJECTED` and never derives a
hypothesis. Every other operation and code stays `LDAP_ERRORS`; the finding labels carry `pool`, `op`, and `code`
(`network` and `other` mean a failure below the LDAP protocol). Plugin calls that ended `canceled` (client gone) or
`admission_limited` (host capacity) and Lua VM pools of other roles are not backend evidence and are not counted.
`auth_backend` findings are labeled with `kind` (`plugin`, `lua`, `application`) and `name`; a Lua backend that
fails without replacing its VM, and a plugin that reports a fault inside a successful result, are not visible here.

### `loki` (optional, historical)

Only the compiled `nauthilus_diagnostics` profile runs: instant metric queries
`sum by (<instance_label>) (count_over_time(<selector> |~ "<msg field pattern>" [<window>s]))` plus one coverage query
without a line filter. The pattern matches the literal only as the complete `msg` field of a slog JSON line
(`"msg":"<literal>"`) or text line (`msg="<literal>"`); both encoders escape quotes inside values, so text a client
typed (for example a username) can never be counted as a symptom. This requires Loki to store the raw slog line of
the JSON or text handler: a shipper that wraps lines (for example unparsed Docker `json-file` records with escaped
quotes) or the coloured console format makes every symptom query miss while the coverage query still counts lines,
so the components would read `not_observed`. Check one known message with a manual query when connecting a new
log pipeline. The selector, tenant (`X-Scope-OrgID`), credentials, and endpoint are fixed in the configuration; no
caller value reaches a query, no log line leaves Loki, redirects are never followed, and answers are bounded by
`max_response_bytes` and `max_series` (truncation marks the source `partial`). Windows above `max_time_window` are
clipped to their newest part (`LOKI_WINDOW_CLIPPED`). The literals are bound to the log messages of the code base by
a test:

| Component | Symptom | Log message |
|---|---|---|
| `ldap` | `LDAP_CONNECTION_ERROR` | `LDAP connection error` |
| `ldap` | `LDAP_CONNECTION_FAILED` | `LDAP connection failed` |
| `ldap` | `LDAP_SEARCH_ERROR` | `LDAP search error` |
| `auth_backend` | `AUTH_BACKENDS_FAILED` | `All backends failed` |
| `auth_backend` | `UNCLASSIFIED_BACKEND_TEMPFAIL` | `Unclassified backend error answered as a temporary failure` |
| `redis` | `REDIS_PIPELINE_ERROR` | `Redis batching pipeline returned error` |
| `redis` | `REDIS_WRITE_PIPELINE_FAILED` | `Execute write pipeline failed` |
| `clickhouse_export` | `CLICKHOUSE_FLUSH_FAILED` | `clickhouse pending batch flush failed` |

### `prometheus` (optional, historical and cluster-wide)

Complements the instance-local runtime view: it asks one Prometheus for every scraped instance and ties the counts to
the requested window. Only the compiled `nauthilus_diagnostics` profile runs: instant queries of the form
`sum by (<instance_label>) (increase(<series>{<selector>}[<window>s]))`, evaluated at the end of the window, over the
same counter families and the same classification as the runtime source:

| Component | Symptom | Series |
|---|---|---|
| `ldap` | `LDAP_BIND_REJECTED` | `ldap_errors_total{op="bind",code="49"}` |
| `ldap` | `LDAP_ERRORS` | every other `ldap_errors_total` series |
| `auth_backend` | `PLUGIN_BACKEND_CALL_FAILURES` | `plugin_calls_total{extension_point="backend",result=~"error\|panic\|timeout"}` |
| `auth_backend` | `LUA_BACKEND_VM_REPLACED` | `lua_vm_replaced_total{key=~"backend:.+"}` |
| `auth_backend` | `AUTH_APPLICATION_ERRORS` | `auth_application_errors_total` |
| `redis` | `REDIS_POOL_TIMEOUTS` | `redis_connection_timeouts_total` |
| `auth_event_delivery` | `AUTH_EVENTS_DROPPED` | `plugin_auth_events_total{outcome="dropped"}` |
| `clickhouse_export` | `CLICKHOUSE_FLUSH_FAILED`, `CLICKHOUSE_ROWS_DROPPED` | the plugin's scoped flush and enqueue counters with a failure `result` |
| `policy` | `POLICY_CHECK_TECHNICAL_ERRORS` | `policy_check_technical_errors_total` |

Gauges (LDAP target health, breaker state, monitored backend servers) stay with the runtime source. The ClickHouse
streams are matched by name pattern; because `increase()` drops the metric name, those two queries keep the family as a
label (`label_replace`) and run on a subquery with a 15-second step, so streams that share every other label never
collide.

The selector (for example `{job: nauthilus}`), tenant (`X-Scope-OrgID`, read by Mimir and Cortex), credentials, and
endpoint are fixed in the configuration; no caller value reaches a query, no series leaves Prometheus, redirects are
never followed, and answers are bounded by `max_response_bytes` and `max_series` (truncation marks the source
`partial`). Windows above `max_time_window` are clipped to their newest part (`PROMETHEUS_WINDOW_CLIPPED`). Failure
codes are `PROMETHEUS_UNREACHABLE`, `PROMETHEUS_QUERY_REJECTED`, `PROMETHEUS_RESULT_TRUNCATED`, and
`PROMETHEUS_TIMEOUT`.

**Coverage.** An instance counts as covered only when the core gauge `nauthilus_version_info` has at least two scrape
samples inside the window (a counter increase needs two). A scrape that drops core metrics (for example a
`metric_relabel_configs` keep rule that lets only plugin metrics through) therefore yields no coverage, and every
requested component reads `unknown` for the deployment instead of a false `not_observed`. Check this once when
connecting a Prometheus: the source report lists the covered instances.

The scrape must keep the families the profile reads: `nauthilus_version_info`, `ldap_errors_total`,
`redis_connection_timeouts_total`, `plugin_auth_events_total`, `policy_check_technical_errors_total`,
`plugin_calls_total`, `lua_vm_replaced_total`, `auth_application_errors_total`, and the ClickHouse plugin streams. A
`metric_relabel_configs` keep rule that already lists the plugin families only needs this alternation added (Prometheus
anchors the expression):

```yaml
metric_relabel_configs:
  - source_labels: [__name__]
    action: keep
    regex: >-
      nauthilus_version_info|ldap_errors_total|redis_connection_timeouts_total|plugin_auth_events_total|policy_check_technical_errors_total|plugin_calls_total|lua_vm_replaced_total|auth_application_errors_total|nauthilus_plugin_.*clickhouse.*_(flush_batches|queued_rows)_total
```

The instance label is the series label that names an instance (`instance` is the scrape address; a relabeled `pod`
label reads better). Values outside a plain pattern are replaced by a digest. Counts are rounded: `increase()`
extrapolates, and a series that first appears inside the window counts only from its second sample, so a restart of the
only instance can hide the first increments.

## 8. Limits and known gaps

- Only Nauthilus as the issuer is supported; external authorization servers are not.
- DCR and Client ID Metadata Documents are not supported for MCP access (deliberate, see section 2).
- The runtime view is one instance; there is no cluster fan-out. Process-lifetime counters are not tied to a window.
- A removed group membership takes effect at the next login, at the latest after `max_authentication_age`; removing a
  client from `static_clients` or a user-wide token revocation takes effect immediately.
- No JSON-RPC batches, no server-to-client requests, no SSE streams (`JSONResponse` mode), no browser clients.
- Loki evidence counts messages; it carries no first/last-seen times and depends on the configured retention.
- Prometheus evidence is only as complete as the scrape: sampling gaps, a relabeling that drops core metrics (reported
  as `unknown`), and counter resets inside the window limit it. It carries no first/last-seen times either.
- History stays bound to its contract (ClickHouse only, 31-day window).

## 9. Verification

- Unit and integration tests: `server/mcpserver` (guards, spoofed `X-Forwarded-For`, bearer matrix, failure limiter,
  metadata, body inspection, all three protocol eras through the SDK client, response cap, byte-for-byte HTTP/MCP
  parity of every operation for results and errors), `server/supportops` and its sources (Loki hits, empty answers,
  outages, truncation, window clipping, query and tenant boundary, anchored message filter against forged fields,
  label digest, literal binding to log calls; runtime rule table), timeouts in both MCP eras, request cancellation,
  shutdown drain,
  `server/supportapi`, `server/idp` (hosted resources, user right, login age, lifetime cap, both token formats),
  `server/handler/frontend/idp` (authorize refusals, RFC 8414, RFC 9207), `server/config` (validation and the example
  through the production loader).
- Real clients (isolated, local Nauthilus with a TLS issuer, Redis, a Lua backend with groups and TOTP, Playwright for
  the browser step): Codex CLI 0.154.0 and Claude Code 2.1.292 completed the OAuth flow with the static client id
  (password, TOTP, consent, `iss` on the callback); Claude Code reported the server as connected and the token Codex
  obtained ran tool calls. Both clients were refused in DCR mode. Refused as well: a user outside the support group
  (`access_denied`), an unlisted static client and a combined resource (`invalid_target`), ID tokens and tokens
  without the resource audience (`401 invalid_token`), and a client removed from `static_clients` (existing token
  `401`, refresh `invalid_target`).
