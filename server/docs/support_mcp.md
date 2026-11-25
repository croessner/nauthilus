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
| Operation table | `server/supportapi` | The six operations and the segment operation, strict argument decoding, rendered result and error bytes, input schemas derived from the management OpenAPI document. Both transports use it, so they cannot drift apart. |
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
| `operational_log_overview` | `POST /api/v1/support/operations/log-overview` | `nauthilus:operations_read` |
| `operational_log_events` | `POST /api/v1/support/operations/log-events` | `nauthilus:operations_read` |
| `support_response_segment` | `POST /api/v1/support/responses/segment` | the scope of the operation that produced the answer |

Both history scopes release the complete recorded data; `nauthilus:history_detail` is kept for existing grants and
grants nothing beyond `nauthilus:history_read`.

`authentication_attempts_search` takes the same optional `response_mode` (`detailed`, `compact`) and
`include_ban_context` arguments as the HTTP route; the tool input schema is generated from the same OpenAPI component,
and the answers are byte-identical. The mode only selects the presentation
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
  `max_response_bytes` per tool result counting the structured content and its text copy (a larger result arrives
  in segments, see "Large answers" below), and `failed_auth_per_minute` failed bearer attempts per client (IPv4 address or IPv6 /64;
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

Answers carry the complete recorded and observed diagnostic data: logins and accounts of every identity in an attempt
or ban (also those behind a shared address), client IPs, protocols, client ids, status texts, factor evidence, error
codes and texts, internal instance and host names, LDAP pool and target names, Redis pool names, Loki and Prometheus
labels, log messages, and every field of a stored log line. Nothing is cut, merged, or masked heuristically. Two
transformations remain:

- **Authentication secrets** are replaced by `<redacted>`. A name is a secret name when its last word (split at `_`,
  `-`, `.`, space, `/`, `:`, brackets, and case changes; digits around a word and a plural `s` ignored) is `password`,
  `passwd`, `passphrase`, `pwd`, `pass`, `pw`, `bindpw`, `passcode`, `passwort`, `kennwort`, `secret`, `token`,
  `authorization`, `cookie`, `assertion`, `jwt`, `otp`, `totp`, `apikey`, or `credential`, or its last two words are
  `api key`, `private key`, `secret key`, `signing key`, `access key`, `client key`, `recovery code`, `totp code`,
  `otp code`, `password hash`, or `code verifier`. So `ldap_bind_password`, `userPassword`, `session_tokens`,
  `password2`, `db:password`, and `X-API-Key` are secrets, while counters and ids such as `current_password_retries`,
  `total_passwords_seen`, `tokens_issued`, or `credential_id` stay complete. `session` and `session_id` are request ids
  in Nauthilus logs and stay. Log fields with a secret name are replaced and named in `redacted_fields`; in an array, the
  item after a secret-named flag item (`["--password","..."]`) is replaced as well.
- **The stored line** of an event gets the same replacements as its fields: a JSON or slog text line is read token by
  token, names and values are decoded (so `"pass\u0077ord"` or an escaped value cannot hide a secret), a secret-named
  value becomes `"<redacted>"`, every other string value passes the free-text rules below and is encoded again only
  when they changed it. Everything else stays byte for byte, repeated names and their order included, so `line`
  decodes to exactly the redacted `fields`. JSON objects and arrays embedded in a text value (a dumped request body) are
  rewritten the same way, in fields, lines, and overview messages; an embedded JSON value that is the value of a
  secret-named assignment (`password=[123456]`, `client_secret: {...}`, `--password ["..."]`) is replaced as a whole.
- Inside free text (messages, error texts, raw lines) only unambiguous secret syntax is replaced:
  signed JWTs, URL passwords, `code`, token, and secret query parameters in URLs, the credential of an `Authorization:
  <scheme> ...` header, a `Bearer`/`Basic`/`Negotiate`/`Digest` word that looks like a credential (digits, base64
  symbols, inner capitals, or 32 characters), the value of a secret-named command-line flag (`--password value`), and
  the values of secret-named assignments in the forms `name=value`, `"name": value` (JSON with any key, also escaped
  inside a string; an object or array value as a whole), `Name:value` without a space (struct dumps), LDIF `name::
  value`, identifiers written `userPassword: value` or `bind_password: value`, and HTTP headers written `X-API-Key:
  value` or `Authorization: value` (the scheme stays visible). Any other `name: reason` with a space is how Go wraps
  errors, so `token: redis: connection pool timeout`, `parse token: illegal base64 data`, `cookie: invalid or tampered
  cookie`, or `Authorization: header missing` stay complete. A quoted value ends at its quote, an unquoted value at
  whitespace or `, ; &` (struct dumps also at a closing bracket, headers at the line end). The event or group then
  carries `secrets_redacted` and the answer `LOG_SECRETS_REDACTED`. Quoted flag values (`--password 'a b'`), values after an escaped newline or
  quote inside a stored JSON line, doubly escaped JSON, quoted values after `name: `, and keys with an annotation in
  parentheses are covered. Not recognized: a password with spaces or those separators in an unquoted value (only its
  first part is replaced; after `userPassword: ` an unquoted value of several words stays, so `userPassword: attribute
  missing` stays readable); prose such as `config password: value` with a space; a value glued to a short flag (`-pvalue`); a short lower-case word after `Bearer` in prose; names outside the
  vocabulary (for example `signature`); and OAuth codes in a `code=` assignment outside a URL (`code` also names error
  codes). A rare `token:reason` without a space, or a placeholder in a usage text (`--password PROMPT`), is replaced
  although it is no secret.
- **Cookies and labels.** A `Cookie:` or `Set-Cookie:` header inside a text is replaced to the line end when its value
  starts with a `name=value` pair or is a bracketed header dump such as `map[Cookie:[a=b; c=d]]` (`cookie: invalid or
  tampered cookie` and `Set-Cookie: header too large` stay). A stream label with a secret name is
  replaced and named as `labels.<name>` in `redacted_fields`; other label values pass the free-text rules.
- **Invisible format characters** (Unicode category Cf, for example bidirectional overrides) are shown as `<U+XXXX>`,
  and invalid UTF-8 bytes become U+FFFD, which JSON cannot carry otherwise. Newlines and tabs stay.

The tool descriptions and the server instructions tell the model to treat every string as untrusted data; this does
not make natural-language content harmless. The data is personal data: grant the support scopes only to staff
entitled to it, and point a model client at the endpoint only if its operator may process that data (a local model
keeps it on premises). Answers are audited per call with the principal, operation, and result count.

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
(`429`), `OPERATIONS_NOT_CONFIGURED` (`503`), `INTERNAL_ERROR` (`500`). The segment operation adds `SEGMENT_UNKNOWN`
(`404`) and, only for an answer larger than the segment store, `RESPONSE_TOO_LARGE`.

### Large answers (`support_response_segment`)

An answer above a transport bound is never discarded. Over MCP the bound is the serialized HTTP response itself:
the JSON-RPC envelope with the request's own id, the text copy (the answer escaped once more as a JSON string), the
structured copy, and the error flag. An answer whose serialized response exceeds `limits.max_response_bytes` is stored
and returned as its first segment: `{"schema_version":"1","segment":{"operation":...,"offset":0,"total_bytes":...,"next_cursor":"..."},"data":"..."}`.
`support_response_segment` with `next_cursor` returns the next segment; concatenating `data` of every segment in order
yields the complete JSON answer byte for byte, so one large log event or a large attempt detail arrives complete.
Segments are kept for ten minutes (64 MiB in total; the oldest go first), bound to the principal that received the
answer (credential method and identity) and to the scopes of its operation, and work over HTTP as well
(`POST /api/v1/support/responses/segment`). One answer can be at most 16 MiB (larger answers are `RESPONSE_TOO_LARGE`;
narrow the request). Each principal holds at most 16 MiB; its own oldest answers go first, never
another principal's. Every segment is rendered to the bound of the call that fetches it, measured the same way, as
the longest part of the answer that fits (a binary search over the part's end that never splits a UTF-8 character),
so every raw MCP response stays within `limits.max_response_bytes`, also for a long request id or an answer dense in
quotes and backslashes. A bound too small for one character of a segment is `RESPONSE_TOO_LARGE`. The store lives in the
instance that produced the answer: behind a load balancer, segment fetches must reach the same instance (sticky
routing), otherwise they answer `SEGMENT_UNKNOWN`. HTTP itself has no answer bound. A segment fetch is a transport call
(the MCP access record covers it); the answer was audited when it was produced. A panic inside any support operation
answers `INTERNAL_ERROR` on both transports and never ends the process.

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

**Windows and parts.** Every window of the operations requests is half open, `[from, until)`, and kept in whole
milliseconds (finer digits are dropped), the precision of a range selector; the answer states the window it used. A
historical count covers exactly that window: an instant query with the window length in milliseconds as its range,
evaluated at the window end, for Loki one nanosecond before it, because Loki counts `(t-range, t]`. No count uses a
range query, so how a query frontend aligns range evaluations (`align_queries_with_step`) never matters. A window
longer than the source's `max_time_window` (the longest span one query covers, default `1h`) is split into
consecutive parts of at most `max_time_window` that end at the window end, and their counts are added; the log events
read part by part. One window takes at most 24 parts, so with `max_time_window: 1h` every window up to the 24-hour
maximum is answered completely. A longer window keeps its newest 24 parts and is stated as clipped
(`LOKI_WINDOW_CLIPPED`, `PROMETHEUS_WINDOW_CLIPPED`, source `partial`). The source timeout applies per part, within
the timeout of the call; a source that runs out of time reports `timeout`. A twelve-hour diagnostics call with eight profile
queries sends 12 × 9 Loki queries, at most four at a time.

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
`sum by (<instance_label>) (count_over_time(<selector> |= "<literal>" |~ "<msg field pattern>" [<window>ms]))` plus one
coverage query without a line filter. The substring stage drops every line without the literal before the pattern
runs, so a query stays cheap on windows with many lines, for example after a restart with debug logging. The pattern
matches the literal only as the complete `msg` field of a slog JSON line
(`"msg":"<literal>"`) or text line (`msg="<literal>"`); both encoders escape quotes inside values, so text a client
typed (for example a username) can never be counted as a symptom. This requires Loki to store the raw slog line of
the JSON or text handler: a shipper that wraps lines (for example unparsed Docker `json-file` records with escaped
quotes) or the coloured console format makes every symptom query miss while the coverage query still counts lines,
so the components would read `not_observed`. Check one known message with a manual query when connecting a new
log pipeline. The selector, tenant (`X-Scope-OrgID`), credentials, and endpoint are fixed in the configuration; no
caller value reaches a diagnostics query (only the log events take a quoted instance and message, section 7.2),
redirects are never followed, and answers are bounded by
`max_response_bytes` and `max_series` (truncation marks the source `partial`). Windows above `max_time_window` are
counted in parts ("Windows and parts" above). The literals are bound to the log messages of the code base by
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
`partial`). Windows above `max_time_window` are counted in parts ("Windows and parts" above); the increase of each
part is estimated by `increase()`, so the sum can differ from one long increase by a fraction. Failure
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
label reads better). Instance values are returned complete. Counts are rounded: `increase()`
extrapolates, and a series that first appears inside the window counts only from its second sample, so a restart of the
only instance can hide the first increments.

### 7.1 Log overview (`operational_log_overview`)

The diagnostics profile counts eight fixed messages; anything else, such as RBL resolver timeouts or WebAuthn warnings,
stays invisible there. The log overview counts every line of the Loki source at the requested levels in a window, one
group per level and exact message text, so messages nobody profiled become visible as well. It needs no configuration
beyond the `loki` source and uses its selector, tenant, credentials, timeout, `max_time_window`, `max_series`, and
`max_response_bytes`.

Request: `schema_version`, optional `window` (default the last 15 minutes, at most 24 hours), optional `levels`
(`error`, `warn`, `notice`, `info`, `debug`; `error` and `warn` when absent), optional `page` (`limit` default 50, at
most 200; `cursor` from the previous answer), and `audit_reference`. Loki receives one coverage query per window part
and, for every bucket (and every part of a bucket longer than `max_time_window`), one instant count per slog encoder,
evaluated one nanosecond before the bucket end, so the overview needs no knowledge of the log format and each count
covers exactly its bucket:

```text
sum by (<instance_label>, nauthilus_level, nauthilus_msg) (count_over_time(<selector>
  |~ "\"level\":\"(ERROR|WARN)\"" | json nauthilus_level="level", nauthilus_msg="msg"
  | __error__="" | nauthilus_level=~"ERROR|WARN" [<bucket>ms]))
```

and the same with the text filters `!~ "^\s*\{" |~ "(^|\s)level=(ERROR|WARN)(\s|$)"` and `| logfmt`. A text line
fails the JSON parser and is dropped by `__error__=""`; the non-strict logfmt parser does not fail on a JSON line, so
the text query excludes JSON lines first, and a `level=ERROR` typed into a JSON value never counts. Only level names of
the fixed vocabulary reach the query. The label extraction parameters of `json` and `logfmt` need Loki 2.9 or newer;
an older Loki rejects both queries and the source reads `unavailable`.

The answer holds:

- `source`: the Loki report with status, code, truncation, and the coverage (instances that logged any line in the
  window, covered time span). An instance in the coverage without a message group logged nothing at these levels.
- `buckets` and `bucket_seconds`: up to 12 buckets that tile the window exactly and end at its end. Every bucket spans
  `bucket_seconds` (a whole number of seconds), except the first, which starts at the window start and may be
  shorter. A line counts in the bucket whose `[from, until)` holds its time, so the bucket counts add up to exactly the
  lines `operational_log_events` returns for the same window and filters.
- `messages`: one page of groups, most frequent first (more severe levels first at equal counts), each with `id` (its
  position in the whole answer), `level`, the complete `message`, the total `count`, one count per bucket in `counts`,
  `first_bucket_from` and `last_bucket_until` of the buckets with a count, and the per-instance counts. Identical
  messages of several instances share a group; different messages never do. `message_exact` is true when the message
  is the stored text unchanged; only then does it work as the `message` filter of `operational_log_events` (otherwise
  filter by instance and the group's buckets). A message of the diagnostics profile
  carries its `component` and `symptom`.
- `page`: `limit`, `offset`, `total` (every group of the answer), and `next_cursor` (null on the last page).
- `notes`: always `VALUES_ARE_UNTRUSTED_DATA` and `LOG_MESSAGES_ARE_NOT_INCIDENTS`; when they apply
  `LOG_SECRETS_REDACTED`, `LOG_MORE_PAGES`, `LOG_PAGES_REQUERY_THE_SOURCE`,
  `HISTORICAL_SOURCE_INCOMPLETE` (partial, clipped, truncated, or timed out), `NO_HISTORICAL_SOURCE`, and
  `LOG_NO_COVERAGE` (no instance logged any line in the window: check the selector and retention).

Every group has the status `observed`. A counted warning is evidence that a code path logged, not an outage: retries,
fallbacks, and client errors log warnings during normal operation. The overview derives no hypotheses and never
reports `failing` or `degraded`; use `operational_diagnostics` and the runtime source for component state, and
`operational_log_events` with a group's `message` (and an instance) to read its stored lines.

**Pages.** Every page runs the Loki queries again for the same window and returns the groups from the cursor offset.
A cursor carries the window of the first page, so a follow-up may repeat the request without `window` (an explicit
window must be the same); a cursor of another window or level set is `INVALID_CURSOR`. A window in the past is stable; a window that still
receives lines can shift between pages (`LOG_PAGES_REQUERY_THE_SOURCE`).

**Bounds.** `max_series` bounds the series per count query (instance × level × message); a truncated answer keeps the
first series in label order and marks the source `partial` with `truncated: true`. A response above
`max_response_bytes` drops that count (`LOKI_RESULT_TRUNCATED`). A failed count makes the source `partial`; when every
count fails, the source is `unavailable`, never an empty `ok`. Windows above `max_time_window` are counted in parts
("Windows and parts" above). Messages with variable content (counters, addresses) are separate groups and raise the
series count; a Loki `max_query_series` limit below the series count rejects the query. A window of 1 hour sends 25
instant queries (one coverage, 12 buckets × 2 encoders), a 24-hour window with `max_time_window: 1h` 72 (24 coverage
parts, 12 buckets of two parts × 2 encoders), at most four at a time.

### 7.2 Log events (`operational_log_events`)

The log events return the stored lines themselves, newest first: everything a group of the overview counted, with its
timestamp (nanoseconds), instance, stream labels, and every field of the line.

Request: `schema_version`, optional `window` (as above), optional `levels` (as above), optional `instance` (exact
instance label value, at most 256 characters), optional `message` (exact message, at most 4096 characters, for example
the `message` of an overview group), optional `page` (`limit` default 100, at most 500; `cursor`), and
`audit_reference`. Loki receives one log query per slog encoder:

```text
{<selector>} | <instance_label>="<instance>" |~ "\"level\":\"(ERROR|WARN)\""
  | json nauthilus_level="level", nauthilus_msg="msg" | __error__="" | nauthilus_level=~"ERROR|WARN"
  | nauthilus_msg="<message>"
```

with `direction=backward` and `limit`, and the same for the text encoder. The instance and the message are the only
caller values that reach a query; both are rendered as quoted LogQL strings, so they can neither close the selector nor
add a pipeline stage, and the instance is a label filter after the fixed selector, so it can only narrow it. The lines
of both queries merge in one unique order: newest first, then by the complete stream label set, then by line, so pages
are stable even when two streams hold the same line at the same time.

Every event holds `at`, `instance`, `level`, `message`, `format` (`json`, `logfmt`, or `raw` for a line that is
neither), `line` (the complete stored line), `labels` (stream labels without the parser labels), and `fields` with every
field of the line, nested objects included and numbers as written. A name the line repeats keeps every value: its field
is the list of all values in line order, and `repeated_fields` names it. Secrets are replaced as described in section 3,
in `line`, `fields`, and `labels`, and named in `redacted_fields` (dotted paths) or flagged with `secrets_redacted`.

**Pages.** `next_cursor` continues before the time of the last returned line and skips the lines already returned at
exactly that time. Loki cuts a run of lines with one timestamp in its own order, so a page only uses lines that are
newer than the oldest line of a full read; within that part every run is complete and sorted the same way on every
page, and no line is repeated or skipped. When a run is larger than one read (the read grows up to 5000 lines, the
usual Loki entry limit), the run is paged stream by stream: the streams with data at that time come from the Loki
series listing in label-set order, each stream's lines at that time are read whole and sorted by line, and the cursor
names the stream (index and digest) and the lines done from it on; done lines spill over into the following streams,
so lines a normal page returned before the hand-over are never repeated. A page of a run reads at most 16 streams.
The stream listing holds up to 5000 streams (it does not use the `max_series` bound of metric answers); streams beyond
it are one gap `STREAMS_EXCEED_LISTING_BOUND` at that time, and a listing that fails is one gap `STREAMS_UNLISTED`
(`LOKI_STREAMS_UNLISTED`); paging continues before that time in both cases. Inside a run the source reads it stream by stream
directly; a read without line texts is only used to find the time of the next line, so a Loki that merges equal probe
lines cannot shift a position. A single
stream with more lines at one timestamp than one read returns is listed in `gaps` with its time, labels, and
`STREAM_RUN_EXCEEDS_READ`, and paging continues with the next stream and the older lines; the lines of that run are
not returned. They are not reachable by further splitting today: Loki cuts a run of one stream and one timestamp in
its own order, a log query offers no position inside such a run, and identical lines cannot be told apart at all.
Splitting by line content (regular-expression prefixes) would reach distinct lines but needs one query per prefix
range and a cursor holding the prefix, and it still cannot separate identical lines; it is not implemented. Raise
Loki's `max_entries_limit_per_query` only together with the read size of this source, which is fixed at 5000 lines. A page can hold fewer lines than `limit` and still
carry `next_cursor`. A cursor carries the window and binds to the levels, instance, and message; a follow-up may omit
`window`. Cursors are not signed, so they work on every instance of a deployment; every field is validated and
bounded, and an edited cursor can only move its own pages. When the streams of a run change between pages (a window
that still receives lines), the source reads `partial` with `LOKI_STREAMS_CHANGED`; when done lines meet a gap stream,
they are dropped (`LOKI_RUN_POSITION_RESET`), so lines may repeat but never vanish.

When a Loki answer exceeds `max_response_bytes`, the read halves down to one line: `page.limit_applied` is then below
`page.limit` (`LOG_PAGE_REDUCED_BY_SOURCE_LIMIT`), and the cursor continues without a gap. A line larger than the
bound itself is found by a read without line texts and read with its stream at its time; when that read still exceeds
the bound, the stream's lines at that time are listed in `gaps` with `LINES_EXCEED_SOURCE_BYTE_BOUND` (raise the
source's `max_response_bytes` to read them), and paging continues. Every page with a gap reads `partial` with
`LOKI_GAPS`; nothing is skipped without a gap entry. One read spans at most `max_time_window` before its end ("Windows
and parts" above): when it returns no line, the next older part is read in the same call; when a part ends the read
before the window start, the page carries `next_cursor` at the part start, so a page can hold fewer lines than
`limit` while older parts remain. A part of which nothing could be read (`unavailable`, `timeout`) is never passed
over; the page ends without a cursor and the request can be repeated. One failed encoder query makes the source
`partial`, both `unavailable`. An answer above the MCP bound arrives in segments (section 6, "Large answers").

## 8. Limits and known gaps

- Only Nauthilus as the issuer is supported; external authorization servers are not.
- DCR and Client ID Metadata Documents are not supported for MCP access (deliberate, see section 2).
- The runtime view is one instance; there is no cluster fan-out. Process-lifetime counters are not tied to a window.
- A removed group membership takes effect at the next login, at the latest after `max_authentication_age`; removing a
  client from `static_clients` or a user-wide token revocation takes effect immediately.
- No JSON-RPC batches, no server-to-client requests, no SSE streams (`JSONResponse` mode), no browser clients.
- Loki diagnostics evidence counts messages; it carries no first/last-seen times and depends on the configured
  retention. The log overview resolves time only to its buckets; the log events carry the exact time of every line.
- History pages hold at most 200 events of an attempt, 500 contributions, and 50 claimants of a ban; each list
  continues with its cursor ([support_authentication_history.md](support_authentication_history.md), "Inner lists").
  The lifecycle rows of one network are bounded (`LIFECYCLE_ROWS_TRUNCATED`, newest kept) without a continuation.
- Prometheus evidence is only as complete as the scrape: sampling gaps, a relabeling that drops core metrics (reported
  as `unknown`), and counter resets inside the window limit it. It carries no first/last-seen times either.
- History stays bound to its contract (ClickHouse only, 31-day window).

## 9. Verification

- Unit and integration tests: `server/mcpserver` (guards, spoofed `X-Forwarded-For`, bearer matrix, failure limiter,
  metadata, body inspection, all three protocol eras through the SDK client, response cap, byte-for-byte HTTP/MCP
  parity of every operation for results and errors), `server/supportops` and its sources (Loki hits, empty answers,
  outages, truncation, window clipping, query and tenant boundary, anchored message filter against forged fields,
  verbatim labels, literal binding to log calls; log overview queries, buckets, truncation, exact grouping, pages, and
  notes; log events queries with quoted filters, format merge, equal-time pages, page shrinking, field parsing, and
  secret replacement; runtime rule table), timeouts in both MCP eras, request cancellation,
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
