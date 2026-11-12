# Nauthilus v4 Module Migration

Nauthilus v4 moves the Go module identity to
`github.com/croessner/nauthilus/v4`. This major version reflects the operator
configuration break introduced by the top-level Policy configuration model.

## Go Consumers

Go source that imports Nauthilus packages must replace the exact module prefix
`github.com/croessner/nauthilus/v3` with
`github.com/croessner/nauthilus/v4` and then update its module dependency.
Third-party module paths that independently use a `/v3` suffix are unrelated
and must not be rewritten.

## Native Plugins

Native `.so` plugins must be rebuilt against the v4 `pluginapi/v1` package and
the same Go toolchain, build tags, relevant build flags, and dependency sources
as the v4 host. An artifact built against the v3 module identity is not binary
compatible with the v4 host even though the semantic plugin API identifier
remains `nauthilus.plugin.v1`.

## gRPC Consumers

The Go `go_package` ownership metadata now points to the v4 module. The
protobuf package names, service names, method names, message field numbers,
and HTTP paths are unchanged. Clients that use independently generated stubs
therefore remain wire-compatible and do not need to adopt the Nauthilus Go
module solely for this migration.

Public descriptor checks normalize Go package ownership back to the reviewed
legacy metadata before comparing Common, Auth, and Identity with their frozen
baseline. Policy has its own frozen baseline and receives the same
normalization. Any other descriptor change remains a compatibility failure.

## Release Identity

Release tags must use the same major version as the module path. The release
metadata guard rejects a tag whose major differs from `go.mod`; for this module
the intended first prerelease is `v4.0.0-alpha.1`.

## Stable v4.0.0 Security Baseline

The stable release requires Go 1.27.2 and `golang.org/x/net` v0.60.0,
including their matching vendored dependencies. These upstream updates fix
the HTTP, TLS, MIME, and template vulnerabilities reported by the release
vulnerability gate for the previous Go 1.27.1 build. The failing vulnerability
scan is the dependency regression evidence; application-level workarounds
are not used in place of the upstream fixes.

Rebuild all private native plugins, including `rns_auth` and `mailde_auth`,
against the stable release source and exact toolchain. Earlier prerelease
plugin binaries must not be reused. Deploy the host image, plugin checksum
and signature, and immutable plugin directory as one compatible release.

## v4.0.8: DNS Lookup Retries And Socket Pool

- All outbound DNS lookups (RBL checks, the client IP reverse lookup, the
  Lua `nauthilus_dns` module, and the connection monitor) share one
  long-lived client. See `server/docs/dns_client.md`.
- A lookup now sends up to `runtime.clients.dns.attempts` queries
  (default `3`) inside `runtime.clients.dns.timeout`. An additional
  attempt starts after each `runtime.clients.dns.retry_interval` (default
  `timeout / attempts`) while earlier attempts keep running, and the first
  definitive answer wins. Before, one lost UDP datagram always ended in
  `lookup <name>: i/o timeout` after the full timeout. Set `attempts: 1`
  to keep the previous single-query behavior.
- This default applies without a configuration change. A slow or lossy
  resolver can receive up to `attempts` queries per lookup.
- "Name does not exist" ends a lookup without a retry, so RBL lookups for
  unlisted addresses still send one query.
- `runtime.clients.dns.pool_size` (default `0`, disabled) keeps that many
  idle UDP sockets per resolver and reuses them instead of opening one
  socket per query. `runtime.clients.dns.pool_max_uses` (default `256`)
  replaces a socket after that many queries. A socket whose query stayed
  unanswered is closed and not reused.
- New metrics: `dns_lookups_total{result,attempts}` counts finished
  lookups (`result` is `success`, `not_found`, `timeout`, or `error`), and
  `dns_pool_sockets_total{source}` counts pooled queries by socket source
  (`reused` or `new`).
- The new settings require a restart, like the existing DNS settings.
- Lookup results, RBL scoring, and error handling are unchanged.
- The toolchain moves to Go 1.27.4. Go 1.27.3 carries a `net/http`
  vulnerability (GO-2026-6859, HTTP/1 server crash through a
  `MaxBytesReader` header race) that is reachable in the server.
- `pluginapi/v1` is unchanged. Rebuild every private native plugin,
  including `rns_auth`, against the exact v4.0.8 source and Go 1.27.4.

## v4.0.7: Request Termination Causes And Cancel Sources

- The HTTP server records why a connection ended (client disconnected,
  connection deadline exceeded, connection closed locally, connection
  failed) and attaches it to the request context.
- A request ended by the client logs `msg="Client Closed Request"` at
  NOTICE with `status=499`, the level of `Processing incoming request`.
  v4.0.6 logged it at WARN; development builds after v4.0.6 logged INFO.
  Alerts or queries that select it by level must use NOTICE.
- A request whose connection ended for a server-side reason logs
  `msg="Request connection terminated"` at WARN.
- Both lines carry `error` with the transport cause (for example
  `client disconnected: read tcp ...: connection reset by peer`) and
  `duration_ms` since the request entered the server. HTTP auth requests
  also carry `client_ip` and `protocol` once the auth handler has resolved
  them.
- `Authentication application failed` (HTTP and gRPC) and
  `Native plugin call failed` carry the state of the failing request's own
  context: `request_context_error` (`context canceled`,
  `context deadline exceeded`, or empty while it is active),
  `request_context_cause` (for example `client disconnected: ...`), and
  `cancel_source`:
  - `request`: the own request context ended, typically because the
    client closed the connection.
  - `foreign`: the error carries a cancellation or deadline although the
    own request context is still active. The cancellation came from work
    shared with another request (deduplicated lookups) or from an internal
    deadline; for plugin calls, `plugin_result=timeout` identifies a
    per-call deadline.
  - empty: no cancellation is involved.

  The own request state is read when the line is written: `foreign` is
  certain, while `request` can also mean that the client disconnected
  after a foreign cancellation had already failed the request.
- `Native plugin call failed` adds these fields only for request-bound
  calls; lifecycle calls, plugin workers, and work detached from an ended
  request do not carry them. Plugin calls that start after the request
  context ended run on the service context and carry none of them
  either.
- gRPC answers an application error that wraps a cancellation or
  deadline with the `Canceled` or `DeadlineExceeded` status, as before,
  so such calls write no `Authentication application failed` line.
- The terminal tempfail WARN line (`msg="Temporary server problem, try
  again later"`) carries the same three fields, read from the own
  transport request. `cancel_source` is derived from the first technical
  error the request recorded; today that is a brute-force storage error,
  including an unavailable RWP verdict, whichever `tempfail_reason` the
  line names. Policy evaluation failures expose only a status code, so
  without such an error the line shows `request` or an empty
  `cancel_source`; for a failing native plugin, correlate the `session`
  with `Native plugin call failed`, which carries its own `cancel_source`.
- The field names match the Lua runtime cancel diagnostics, whose
  `cancel_source` keeps its own values (`request_context`, `none`, ...).
- Authentication decisions, temporary failures, and response bodies are
  unchanged.

## v4.0.6: Username Syntax, Tempfail Causes, And Identity Lookup Checks

- Usernames are rejected only for invalid UTF-8 and control characters.
  Spaces and IMAP atom specials such as `Max Mustermann`, `(`, `)`, `{`,
  `%`, `"`, and `\` reach the backends, which decide whether the account
  exists; percent-decoded nginx headers like `Vorname%20Nachname` are no
  longer refused. An unsafe authenticate username is answered like an
  empty one with `Invalid login or password` instead of `400 Bad Request`
  for HTTP and gRPC. A missing username key stays `400`, and
  `lookup_identity` over gRPC keeps `InvalidArgument`.
- LDAP filters expand the legacy `%s` placeholder and `%{...}` macros in
  one pass, so a username that contains macro syntax stays literal.
- Every temporary failure writes the terminal WARN line, including
  decisions without a selected policy rule (provider outage, evaluation
  failure, auth FSM guard) that previously ended without a log line, and
  JSON and CBOR requests. The line uses `Temporary server problem, try
  again later` as `msg` and names the cause with `tempfail_reason`,
  `checkpoint`, `status_code`, `policy_set`, `policy_rule`, and
  `outcome_marker`. Log queries matching the old `msg="Temporary server
  problem"` still match it as a prefix.
- `status_message` in the summary log lines, Lua `request.status_message`,
  and native post-action snapshots (for example ClickHouse `status_msg`)
  report the text the client receives, including
  `auth.response.failure_message` and `auth.response.tempfail_message`.
- `lookup_identity` (HTTP `mode=no-auth`, gRPC `LookupIdentity`, IdP
  no-auth lookups) no longer schedules the TLS-encryption and RBL checks
  by default; the built-in plan runs only the Lua environment, as the
  runtime always did. A domain plan that binds `authn/builtin/tls_encryption`
  or `authn/builtin/rbl` to `lookup_identity` now actually runs them in
  no-auth mode; an RBL opt-in multiplies block-list query volume and quota
  cost because lookup traffic is usually far higher than login traffic.
- Configuration load rejects `authn/builtin/brute_force` and
  `authn/builtin/relay_domains` bindings to `lookup_identity`, which were
  silent no-ops before. Remove such `actions` entries before upgrading.
- `Native plugin call failed`, `lua_vm_acquire_failed`, and the LDAP pool
  `reply_channel_blocked_drop` warning carry the request `session`.
- The identity-proxy E2E stack moved to the 38080-38083 and 39094-39444
  port block and stops before starting when another process holds one of
  its ports.
- `pluginapi/v1` is unchanged. Rebuild every private native plugin,
  including `rns_auth` and `mailde_auth`, against the exact v4.0.6 source
  and Go 1.27.3.

## v4.0.5: Credential Result In Logs And Subject Rejection State

- The final auth log field `authn` reports the credential check, taken from
  the host-frozen verdict. A verified password that a subject source rejects
  afterwards, for example because the protocol is inactive, now logs
  `authenticated=fail authz=false authn=true` instead of `authn=false`.
  Wrong or empty credentials, rejections before the credential check, and
  technical failures keep `authn=false`. Subject sources and plugin patches
  cannot raise the logged value. Log queries that read `authn=false` as
  "denied" must use `authenticated` instead.
- A Lua subject rejection or Lua subject error now leaves the request
  unauthenticated, as a native subject rejection already did. Post-actions
  and request snapshots see a failed login with the failure status code
  instead of HTTP 200 and OK, and `run_if: authenticated` providers and
  password checks such as `haveibeenpwnd` no longer run after a Lua
  rejection. Access decisions do not change.
- `pluginapi/v1` is unchanged. Rebuild every private native plugin,
  including `rns_auth` and `mailde_auth`, against the exact v4.0.5 source
  and Go 1.27.3.

## v4.0.4: go-jose Update And Auth Setup Cleanup

- `github.com/go-jose/go-jose/v4` moves to v4.1.6 for GHSA-mgcc-cww5-fp2q
  (denial of service when parsing JWKs with RSA keys). The module is an
  indirect dependency of the OIDC test client.
- The unused core HTTP auth setup path is removed: `core.NewAuthStateWithSetupWithDeps`,
  the `FinishSetup` method of `core.State`, `AuthState.SyncLoginAttemptsFromHeader`
  with `LoginAttemptManager.InitFromHeader`, and the setup errors
  `ErrEmptyUsername`, `ErrEmptyPassword`, `ErrInvalidUsername`, and
  `ErrPasswordEncoding` from `server/errors`. Every HTTP auth surface already
  used the shared auth application adapter, so request handling does not
  change. Go code that imported these symbols must use the auth application
  service instead.
- RBL policy facts are created through one shared constructor; behavior is
  unchanged.
- `pluginapi/v1` is unchanged. Rebuild every private native plugin,
  including `rns_auth`, against the exact v4.0.4 source and Go 1.27.3.

## v4.0.3: Empty Credentials, Operator Response Texts, And RBL Analytics

- An empty username or password value is no longer a malformed request. HTTP
  JSON, CBOR, form, header, nginx, and Basic requests and gRPC `Authenticate`
  answer it as an ordinary failed login with `Invalid login or password`
  through the builtin `standard_empty_username` and `standard_empty_password`
  rules. A missing credential key, JSON or CBOR `null`, and an invalid
  non-empty username still return `400 Bad Request`. For HTTP header
  transports an absent header is a missing key and a present empty header is
  an empty value. `lookup_identity` keeps its temporary failure through the
  new `standard_lookup_identity_empty_username` rule. Empty-credential
  failures run no backend and do not update brute-force buckets.
- `auth.response.failure_message` and `auth.response.tempfail_message`
  override the generic `Invalid login or password` and temporary-failure
  texts in HTTP `Auth-Status` headers, plain-text bodies, and gRPC authority
  responses. Empty values keep the built-in texts; control characters and
  texts longer than 256 characters are rejected at load time. A configured
  text is also its i18n key, so a Policy localization catalog may translate
  it. Specific reasons such as missing TLS, Policy-selected response messages,
  internal diagnostics, logs, and analytics rows keep their texts, and the IdP
  login form keeps its bundled translations. The gRPC authority binds the texts
  at startup, so a change needs a restart there. gRPC list-accounts metadata
  sends non-ASCII status texts through `auth-status-bin` and `auth-error-bin`.
- Native plugins receive `RequestSnapshot.Diagnostics.RBLMatchedLists` with
  every configured RBL list that listed the client IP, in configuration
  order, also below the RBL threshold. The slice is shared with the host and
  read-only. RBL list facts, including `auth.rbl.matched_lists`, are now
  deterministic and in configuration order.
- The host publishes `plugin.exchange.feature.rbl` and
  `plugin.exchange.feature.brute_force` when the RBL threshold is reached or a
  brute-force bucket triggers. The native ClickHouse plugin therefore lists
  `rbl` and `brute_force` in `decision_sources`, in the standard exchange
  order. Dashboards migrating from `actions/clickhouse.lua` rows should query
  membership, for example `has(splitByChar(',', decision_sources), 'rbl')`,
  instead of exact strings.
- The native ClickHouse plugin writes the new `rbl_lists
  Array(LowCardinality(String))` column. Existing installations must run
  `ALTER TABLE nauthilus.logins ADD COLUMN IF NOT EXISTS rbl_lists
  Array(LowCardinality(String)) AFTER decision_sources;` from
  `contrib/clickhouse-kubernetes/schema.sql` before deploying the plugin.
  The Lua `actions/clickhouse.lua` action is retired and receives neither
  change.
- `github.com/andybalholm/brotli` v1.2.7, `github.com/klauspost/compress`
  v1.20.2, and `golang.org/x/net` v0.62.0 fix GO-2026-6888, GO-2026-6865,
  and GO-2026-6860, which the release vulnerability gate reported as
  reachable. GO-2026-6909 in `github.com/crewjam/saml` has no fixed version
  and is reachable only from the `contrib/saml2testclient` SP test tool; the
  gate excludes that tool as a documented maintainer exception while the
  server stays fully scanned.
- `pluginapi/v1` gains one field. Rebuild every private native plugin,
  including `rns_auth`, against the exact v4.0.3 source and Go 1.27.3.

## v4.0.2: DKIM2 Intelligence Plugin Moved Out Of The Core

The DKIM2 intelligence plugin (`dkim2-intelligence`, module
`dkim2_intelligence`) is no longer part of this repository or of the stable
and debug images. It is maintained as an external native plugin, like
`rns_auth`, and it also owns the DKIM2 Policy integration: its verifier
contract, wire example, and reference Policy configuration. Future DKIM2
protocol changes are released with that plugin and need no core change.

- The toolchain moves to Go 1.27.3. Go 1.27.2 carries a `crypto/x509`
  vulnerability that the release vulnerability gate reports as reachable
  through JWT verification. `github.com/getkin/kin-openapi` moves to v0.149.0
  for two published OpenAPI parser issues. Rebuild every private native
  plugin, including `rns_auth`, with Go 1.27.3 against the v4.0.2 source.
- The images bundle `geoip`, `clickhouse`, `haveibeenpwnd`, and `reputation`
  only. `/usr/local/lib/nauthilus/plugins/dkim2-intelligence.so` and its
  `.minisig` are no longer shipped.
- Operators who load `dkim2_intelligence` must supply the external artifact
  built from the exact v4.0.2 release source tree, toolchain, and build tags,
  with its checksum and detached signature, in the immutable plugin directory.
  An artifact built for an earlier release, including the one bundled with
  v4.0.1, is rejected before `plugin.Open` because its native artifact
  identity no longer matches the host.
- The generic Policy layer, the native plugin loader, and the `reputation`
  and `geoip` plugins are unchanged. Existing `policy` targets, providers, and
  plugin bindings that reference the DKIM2 namespace keep working once the
  external artifact is installed. `pluginapi/v1` is unchanged.
- `scripts/convert-static-reputation.py` now converts only reputation
  overrides and `ip_override_networks`. It rejects `contracts` input, because
  signer contracts and their Policy guards belong to the external plugin. New
  overrides record origin `cutover.static_reputation_v4`. The admin client
  still accepts artifacts written by earlier converter versions and ignores
  their `identity_contracts` and `policy_rules` sections.

## Changes Between v4 Prereleases

- `nauthilus -d` prints a dump of the built-in defaults, not a loadable
  profile: secrets such as `storage.redis.password_nonce` and
  `storage.redis.encryption_secret` print empty and LDAP pool sizes such as
  `auth_pool_size` and `lookup_pool_size` print as `0`; set them before the
  output can be used as a configuration.
- Client addresses of `POST /oidc/register` (the dynamic client registration
  budget) and of native plugin hooks are resolved with the common resolver and
  follow `runtime.servers.http.trusted_proxies`, like the rest of the request
  pipeline, instead of Gin's `ClientIP`. When a trusted proxy sends an
  `X-Forwarded-For` chain that cannot be parsed, the direct peer address is
  used; the former fallback to a client-supplied `X-Real-IP` no longer
  applies. Go consumers of the module: `util.RequestClientIP` was removed; use
  `util.RequestClientIPWithConfig`, which trusts no proxy and returns the
  direct peer when no configuration is passed.
- `storage.redis.batching` caveat: the batching hook drains its queue with a
  single flush worker per Redis client, so every single command of that
  client is serialized behind that worker. Under concurrent load callers wait
  in the queue; a load test measured waits of up to 1.7 s per command and
  authentication timeouts at about 40 logins/s across 3 pods. The brute-force
  paths no longer depend on the hook: since `v4.0.0-beta.8` they issue their
  own explicit pipelines, which the hook passes through unchanged. Leave
  batching disabled (the default) unless a measurement on your own workload
  shows a gain.
- A `storage.redis.sentinels` block whose fields are all empty, as printed by
  `nauthilus -d`, is treated as "Sentinel not configured" and no longer fails
  validation with `master` `required`. As soon as any Sentinel field is set,
  the block is validated strictly as before, and `addresses` must then list at
  least one Sentinel; `master` with `addresses: []` fails validation.
- Remote backend error classes on the edge: `ErrRemoteAuthorityRejected`
  (authority answered `InvalidArgument`, `FailedPrecondition`,
  `AlreadyExists` or `OPERATION_RESULT_CONFLICT`) now wraps the temporary
  backend failure class. The answer stays a temporary failure, but the
  password pipeline classifies it, so the "Unclassified backend error" warning
  disappears. `ErrRemoteCallerRejected` is used only for `UNAUTHENTICATED`; it
  still declines (the next backend decides) and is logged at warning level
  with backend and authority names. `PERMISSION_DENIED` is unchanged: it maps
  to `ErrRemoteOperationDenied`, declines, and is logged at debug level only,
  because the authority also answers it for user-level results.
- Edge nodes discard an authority caller token that the authority rejects.
  On `UNAUTHENTICATED` the edge deletes the cached token from its Redis only
  if the cache still holds exactly that token (compare-and-delete), fetches a
  replacement through the regular refresh path with its distributed lock, and
  retries the RPC once. A second rejection is returned unchanged. Callers that
  lose the refresh lock wait, bounded by `refresh_lock_ttl` and the RPC
  deadline, for the token of the lock holder instead of failing. A guard
  window keeps a permanently rejected edge client from fetching a token per
  RPC: a rejected token that was fetched less than
  `caller_auth.oidc_bearer.token_cache.refresh_lock_ttl` (default 10 s) ago
  is kept, no new token is fetched, and the RPC answers the original
  `UNAUTHENTICATED`; the edge warns about it at most once per window. Cached
  tokens written by earlier prereleases have no fetch time and are replaced on
  the first rejection. The manual flush of the edge authority-token cache
  after an upgrade that invalidates caller tokens (revocation-epoch floor, key
  rotation, client revocation or audience change) is no longer needed. Static
  token files are never replaced or retried, and their rejection is logged at
  debug level only.
- Redis password state uses only the full 64-hex password hash. The eight-hex
  short hash of earlier prereleases is no longer read or written: password
  history sets (`pw_hist`, `pw_hist_ips`), the RWP allowance sets and the
  positive password cache ignore short values, and the admin brute-force flush
  no longer deletes `pw_hist_total` keys, which were never written anyway. No
  cleanup is required. Stray short members in existing history and RWP sets and
  leftover `pw_hist_total` keys expire with their TTL; until then a short member
  only misses a one-time known-password hint and a short positive-cache value is
  a cache miss.
- Brute-force Redis reads and writes are pipelined, which changes the `kind`
  labels of `bruteforce_redis_roundtrips_total`. New labels are
  `pipeline_pw_hist_load`, `pipeline_preauth_check`,
  `pipeline_eval_bucket_counter_save`, `pipeline_affected_account` and
  `pipeline_pw_hist_save`. `pipeline_exists_ban_preresult` and
  `pipeline_exists_ban_policy_facts` now count only fallback reads without a
  pre-authentication prefetch and stay flat on the regular authentication
  path. See section 3.5 of the [brute-force guide](bruteforce_protection.md)
  for the full label table; update dashboards that select on the old labels.
- `redis_write_total` counts every pipelined brute-force script once. Failed-
  login counter writes and failed-password history writes were counted twice
  before, so their share of the rate halves.
- The `bf_update_loop_total` task of the function-duration metric observes the
  batched failed-login counter write once per failed login instead of every
  rule iteration.
- `auth.backchannel.failure_lockout` (introduced in `v4.0.0-beta.5`) was
  removed without a compatibility shim. Backchannel callers are never locked
  out anymore; a genuine caller rejection is delayed by a fixed 300 ms and
  logged at warning level. The key is now rejected like any other unknown
  configuration key, so remove the whole block from the configuration. See
  section 11.1.1 of the [gRPC identity proxy spec](grpc_identity_proxy_spec.md).
- The metric `backchannel_caller_auth_total` lost its `trusted` label and the
  `throttled` outcome. It now carries only `transport` and `outcome`
  (`accepted`, `rejected`, `unavailable`); update dashboards and alerts that
  select on the removed label or outcome.
- The Policy-Basic failure throttler (present since `v4.0.0-alpha.1`) was
  removed. It blocked a username and source address for 5 minutes after 5
  wrong passwords and failed closed for the whole configuration generation on
  any Redis error. A wrong Policy-Basic password is now delayed by a fixed
  300 ms and never blocks; verification no longer uses Redis. Existing
  `nauthilus:policy:basic:{...}` keys are no longer read or written and expire
  on their own. No configuration change is required.
- `GET /livez` is the new liveness endpoint. It checks no dependency and
  answers `200` with the fixed JSON document `{"status":"up"}`. `/healthz`
  keeps its test login, Redis and LDAP checks and is meant only for readiness
  and startup probes. Kubernetes liveness probes that point at `/healthz`
  should switch to `/livez`, because a slow dependency or a busy pod otherwise
  gets healthy pods restarted. `/ping` answers the plain text `pong`, which the
  image's `healthcheck` binary cannot decode, so it is not a valid target for
  that binary. See [Health Endpoints](health_endpoints.md).
- Startup failures are logged once at `ERROR` with the failing startup step,
  for example `start HTTP entry points: privilege drop failed: ...`.
  Previously the reason went through the standard library log bridge at
  `INFO` and was invisible at log level `warn`. The exit code stays `1`. When
  the runtime startup fails, the background Lua script upload is cancelled
  before the startup rollback closes the Redis client.
- The reputation plugin retries transient Redis errors while its storage
  starts: at most 10 attempts within about 50 s, each retry logged at `WARN`
  with an `error_class` field such as `loading`, `connection` or `timeout`.
  Permanent errors fail at once: ACL rejections, Lua script errors, and model
  or allocation identity mismatches. This also applies to a start with
  `allocation_maintenance` enabled. The start error now carries the Redis
  cause; request-time storage errors stay sanitized. The plugin starts before
  the HTTP listener, so the startup probe budget must cover the Redis readiness
  loop of the host (up to 10 attempts 5 s apart) plus this retry before
  `/healthz` can answer. The `startupProbe` example in
  [Health Endpoints](health_endpoints.md) allows 150 s.
- LDAP pool connections now carry the settings of their pool section. Before,
  every pool connection ran with built-in defaults, so `search_timeout`,
  `bind_timeout`, `modify_timeout`, `search_size_limit`, `search_time_limit`,
  `retry_*`, `cb_*`, `health_check_*`, the cache settings, `include_raw_result`
  and `auth_rate_limit_*` were silently ignored for the operations themselves.
  Review these values before upgrading: they take effect now, for example a
  `search_size_limit` on the default section limits every search of that
  section, while a named pool such as a list-account pool keeps its own values.
- Every LDAP pool connection has a default operation timeout: the configured
  `search_timeout`, or 30 s when none is set. Connection setup dials with a 5 s
  timeout and TCP keepalive, and one 30 s deadline bounds the whole connect
  loop including its backoff. Operations on a connection whose server vanished
  without a reset no longer wait for TCP to give up.
- A connect that outlived the 30 s connect timeout and then succeeded could
  deadlock and block the whole LDAP pool until the process was restarted, for
  example after an LDAP server restart under load. The connect loop now uses
  one deadline, and pool maintenance runs in the background: workers no longer
  connect idle slots before each request, and maintenance skips slots that are
  in use instead of waiting for them.
- `/healthz` has a new `ldap_queue` check that makes the instance unready when
  an LDAP pool with a running worker holds queued requests without any worker
  progress for the longer of 30 s and `connect_abort_timeout` plus 30 s (40 s
  by default). See [Health Endpoints](health_endpoints.md).
- An auth request rejected by `auth_rate_limit_per_second` now returns a
  temporary backend failure. The option takes effect with this release, see
  the pool tuning note above.

## Native backend Redis password-cache opt-in

Native backend modules previously bypassed the Redis positive password cache even when `cache` preceded their backend
selector. The default remains disabled. Such configurations now warn at load time instead of silently suggesting Redis
password caching is active. To enable it, rebuild the backend with the optional
`pluginapi.PositivePasswordCacheBackend` declaration and set `plugins.modules[].positive_password_cache: true`, then
restart the matching host/plugin build and retain `auth.backends.order: [cache, plugin(module.backend)]`.

For `mailde_auth`, the backend type registered as `passdb` in Pimparoo's `roles/mde_nauthilus/files/plugin` must implement
`PositivePasswordCacheable() bool` and return true only after auditing credential/identity stability and skipped
`VerifyPassword` side effects (including login logging and POP3 counters). In
`roles/mde_nauthilus/templates/nauthilus.yml.j2`, enable `positive_password_cache: true` on the `mailde_auth` module and
retain the cache-first order and desired `storage.redis.positive_cache_ttl`/`password_nonce`. These external files are not
changed by this host feature. Integer-valued or otherwise non-JSON-round-trippable facts currently bypass Redis caching;
audit actual results before promising a hit rate. The process-local authentication cache remains separate; additional plugin identity scopes guard both caches.

Typed LDAP and Lua authentication providers also preserve a configured cache-first order. Cache lookups accept only
entries from that provider's backend family and configured instances. This includes RNS deployments using
`authn/builtin/ldap_backend` with `order: [cache, ldap, ldap(list-account)]`: `rns_auth` is a subject/environment/post-action
module, not a password backend, and needs no plugin password-cache declaration. LDAP credentials can be cached while
RNS account authorization, GeoIP history and post-actions continue on every request.

Plugin backends whose short-login resolution depends on a domain or tenant header must also implement
`PositivePasswordCacheScopeBackend`. See [additional plugin identity scope](go_plugin_developer_api.md#additional-plugin-identity-scope)
for the shared Redis/in-memory contract and the mail.de domain-resolution requirements.
