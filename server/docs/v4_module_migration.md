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

## v4.1.2: Lua Modules Compiled Once

Nauthilus 4.1.2 is a patch release on the v4 line. The module path,
`pluginapi.APIVersion`, and the configuration roots are unchanged. Private
native plugins must be rebuilt against this source, as for every release.

- A Lua module that a script loads with `require` from the configured
  `package_path` is compiled once when the configuration is loaded. Before,
  every `require` parsed and compiled the module source again, in every
  request and in every Lua runtime: environment sources, subject sources,
  actions, custom hooks, Lua backends, and the cache-flush script. The
  module is still executed for every request; only the compilation is
  shared. Behavior is unchanged.
- In the benchmark `BenchmarkCallEnvironmentLuaSourceWithSharedModules`, an
  environment source request that loads four bundled shared modules dropped
  from about 1.65 ms to 0.29 ms and from about 1.9 MiB to 0.25 MiB of
  allocations per request.
- Documentation: the 4.1.1 notes said that every global variable a callback
  script sets stays in its pooled VM. That is corrected below and in
  `server/lua-plugins.d/POLICY_VM_COMPATIBILITY.md`: a global the script
  assigns is request-local; explicit writes to `_G`, changes to shared
  tables, and globals of required modules persist.

**Action:** none is required.

## v4.1.1: Full Lua API For Authentication Callbacks

Nauthilus 4.1.1 is a patch release on the v4 line. The module path,
`pluginapi.APIVersion`, and the configuration roots are unchanged. Private
native plugins must be rebuilt against this source, as for every release.

### Lua environment sources, subject sources, and actions

Nauthilus 4.0.0 to 4.1.0 ran Lua environment sources, subject sources, and
actions with a reduced host API and rejected a configuration whose callback
used anything else. That limit was never intended and broke callbacks that
worked on Nauthilus 3. Version 4.1.1 removes it: these callbacks run with the
same Lua API as custom hooks and Lua backends.

Available again in environment sources, subject sources, and actions:

- Redis writes, pipelines, scripts, and named pools: `register_redis_pool`,
  `redis_set`, `redis_incr`, `redis_del`, `redis_rename`, `redis_expire`,
  `redis_mset`, `redis_run_script`, `redis_upload_script`, `redis_pipeline`,
  and the hash, sorted-set, list, HyperLogLog, and set write commands.
  `get_redis_connection` accepts named pools and returns a writable handle.
- `nauthilus_cache` write functions: `cache_set`, `cache_delete`,
  `cache_update`, `cache_flush`, `cache_push`, `cache_pop_all`.
- Outbound HTTP (`glua_http`), `nauthilus_mail`, `nauthilus_dns`,
  `nauthilus_soft_whitelist`, and `nauthilus_ldap` when an LDAP backend is
  configured.
- `nauthilus_prometheus.create_summary_vec`, `create_counter_vec`,
  `create_histogram_vec`, and `create_gauge_vec`;
  `nauthilus_psnet.register_connection_target`; the custom-toleration
  functions of `nauthilus_brute_force`; `nauthilus_misc.wait_random`.
- `nauthilus_backend` in subject sources with `get_backend_servers`,
  `select_backend_server`, `get_selected_backend_server`, and
  `check_backend_connection`. A selected server reaches the `Auth-Server` and
  `Auth-Port` response headers again.
- `nauthilus_http_response` in environment sources and subject sources, not
  only in synchronous response actions. Response headers set there reach the
  client; status and body of an authentication response stay with the
  server.
- The standard libraries `os`, `io`, `debug`, `coroutine`, and `channel`,
  including `os.getenv`, and the base functions `print`, `load`,
  `loadstring`, `collectgarbage`, `getfenv`, `setfenv`, `module`, and
  `newproxy`.
- Every bundled helper library, not only `json`: `strings`, `base64`,
  `template`, `tcp`, `http`, `regexp`, `yaml`, `db`, `inspect`, `crypto`, and
  the others. `time` is the complete library again and accepts any time zone.
- `require` with a computed module name.
- `dofile` and `loadfile` in every Lua runtime, including custom hooks, Lua
  backends, init scripts, and the cache-flush script.
- Policy registry scripts run with the complete Lua standard library again.

Further effects:

- The static source check is gone. A script is no longer rejected because a
  forbidden name appears in it, in a shared module it requires, or in a
  string such as `"os"`.
- The shared modules `nauthilus_util`, `nauthilus_keys`, and
  `nauthilus_redis_pool` load in every runtime.
- Candidate preparation compiles every configured callback and no longer
  executes any of them. A script is rejected when it does not compile, or
  when the name of its entry point occurs neither in the script nor in a
  Lua module captured from the configured `package_path`. Module-level code
  runs only with a request, and an unresolvable module name fails when the
  request runs the `require`.
- Each callback has its own pool of pre-built VMs. The callback script
  still runs in a fresh request environment: a global variable the script
  assigns lives only for that request. Nauthilus 4.0.0 to 4.1.0 also rebuilt
  the VM's base global table for every request; 4.1.1 keeps it, as custom
  hooks and Nauthilus 3 do. Explicit writes to `_G`, changes to shared
  tables such as `string`, and globals assigned by a module loaded with
  `require` are therefore visible to later requests of the same callback.
  Do not keep request data there.
- All bundled environment sources, subject sources, and actions pass
  candidate preparation. `server/lua-plugins.d/POLICY_VM_COMPATIBILITY.md`
  no longer classifies any of them as `reference-only`.

What stays as in 4.0 and 4.1.0:

- `require` resolves Lua modules from the files captured from the configured
  `package_path` when the configuration was loaded; `package.path` is empty.
  A changed or added module file becomes active with the next configuration
  reload.
- A POST-Action runs after the response left the server. Its
  `nauthilus_http_response` functions now exist and have no effect; before,
  calling one raised an error.
- `nauthilus_i18n.register_catalog` belongs to init scripts, as in
  Nauthilus 3.
- Generic Policy providers (`kind: lua`) keep their separate sandbox.

**Action:** none is required. Operators who moved logic into a Lua backend,
a custom hook, or a native plugin only to work around the limit can keep that
setup or move it back.

### Loki diagnostics query cost

- The `loki` source of the operational diagnostics filters every profile query
  by its message literal (`|= "<literal>"`) before it applies the message
  pattern. Before, Loki ran the pattern over every line of the window, so a
  window with many lines, for example the 15 minutes after a restart with
  debug logging, exceeded the source `timeout`: the source answered
  `LOKI_TIMEOUT` and its findings read `unknown`. Counted symptoms are
  unchanged.

## v4.1.0: Support History, Scoped Backchannel Credentials, And Brute-Force Toleration

Nauthilus 4.1 is a feature release on the v4 line. The module path,
`pluginapi.APIVersion`, and the configuration roots are unchanged. Items
marked **Action** need an operator decision or a configuration change.

### Upgrade effects

- Every live browser session ends once and stored OIDC consents are requested
  once more, because session-state payloads in Redis are now sealed with
  `storage.redis.encryption_secret` and plaintext records are discarded.
- Consent pages started on a 4.0.x instance must be restarted during a
  rolling update; nothing needs to be migrated.
- Each edge replica fetches its authority token once more, because the cached
  token is now stored encrypted.
- **Action:** rebuild every private native plugin against this source with
  the server PGO profile (`sh scripts/native-pgo-flag.sh` prints the flag). A
  PGO-built server refuses plugins compiled without it.
- **Action:** apply
  `contrib/clickhouse-kubernetes/migrations/diagnostic-contract.sql` before
  deploying the ClickHouse plugin; ClickHouse drops unknown fields silently
  by default.
- **Action:** on Redis Cluster, delete the untagged and
  `{lua-nauthilus}`-renamed `multilayer:global:current_metrics` hashes of the
  bundled Lua plugins once; all other old keys expire.

### Support history, diagnostics, and MCP

- A read-only support history API answers from the evidence the ClickHouse
  plugin recorded: `POST /api/v1/support/authentication-attempts/search`,
  `/api/v1/support/authentication-attempts/detail`, and
  `/api/v1/support/bruteforce-bans/search`, with the scopes
  `nauthilus:history_read` and `nauthilus:history_detail`. It is configured
  under `storage.history.clickhouse` with a dedicated reader account
  (`contrib/clickhouse-kubernetes/history-reader.sql`). Every call is audited
  (`audit=support_history`); without a configured source the routes answer
  `503 HISTORY_NOT_CONFIGURED`.
- The history carries OIDC code issuance and redemption, the answered status
  of a request, and brute-force bans with their contributing attempts. An
  attempt search accepts `response_mode` (`detailed` or `compact`) and
  `include_ban_context`. Recorded free text is sanitized and capped at 256
  characters.
- `POST /api/v1/support/operations/diagnostics` (scope
  `nauthilus:operations_read`) reports findings and hypotheses from the
  instance-local `nauthilus_runtime` source and from the optional `loki` and
  `prometheus` sources under `observability.diagnostics.operations`.
  **Action:** the Loki source needs the raw slog line stored in Loki, and the
  Prometheus scrape must keep the core metric families the query profile
  reads.
- Diagnostics classify `ldap_errors_total` by operation and result code. A
  rejected user password (`bind`, code `49`) is the informational symptom
  `LDAP_BIND_REJECTED`; the `auth_backend` component has runtime evidence
  instead of reading `unknown`.
- An optional read-only MCP endpoint (`runtime.servers.mcp`, disabled by
  default) offers the support tools over OAuth 2.1 with Nauthilus as issuer
  and RFC 9728 protected resource metadata. It accepts pre-registered static
  clients only. New metric `mcp_requests_total{result}`; audit records
  `audit=support_mcp` and `audit=support_operations`.
- The Admin Client gains a `support` command group, `bruteforce list
  --via-mapping`, and the standalone installer
  `contrib/client/install-admin-client.sh`. Repeated `--resolve` flags
  replace `NAUTHILUS_RESOLVE`, and `bruteforce list` requests pages of 100
  entries by default.

### Backchannel caller authorization

- `auth.backchannel.basic_auth.users` defines scoped HTTP Basic credentials
  (`username`, `password`, `scopes`). A scoped credential is authorized like
  a Bearer token carrying those scopes on the HTTP API, the gRPC authority
  listener, and custom Lua and native hooks that declare scopes. The
  top-level `username` and `password` remain the unrestricted credential;
  Nauthilus warns at configuration load while it is configured.
- **Behaviour change:** `nauthilus:authenticate` is no longer a base scope of
  every `/api/v1` route. Each route family asks only for its own scopes;
  `nauthilus:authenticate` opens `/api/v1/auth/*` and the management OpenAPI
  documents. Nothing an existing token could do before is refused now. A
  valid credential without the route scope receives `403`.
- New scopes `nauthilus:security_read` (brute-force and OIDC session
  listings) and `nauthilus:security_write` (cache and brute-force flushes,
  OIDC session deletion). `nauthilus:security` includes both.
- The `/api/v1/support/*` routes accept a scoped Basic credential holding the
  support scopes; the unrestricted credential and `nauthilus:admin` receive
  `403`.
- **Behaviour change:** `auth.backchannel.basic_auth` is validated more
  strictly. `enabled: true` requires the `username` and `password` pair or at
  least one `users` entry, the pair must be set together, usernames must be
  unique and contain neither a colon nor a space, and `users[].scopes` must
  list at least one valid scope. **Action:** check configurations that enable
  Basic authentication before the upgrade.
- **Behaviour change:** a custom hook that declares scopes refuses the
  unrestricted Basic credential with `403` instead of `401`.

### OIDC, browser sessions, and SAML

- **Security fix:** pending consent decisions were stored in the
  authorization-code key space, so a client could redeem the consent
  challenge at the token endpoint and receive tokens before the user
  consented. Consent state has its own key family, and the token endpoint
  refuses code values outside the issued shape with `invalid_grant`.
- **Security:** browser session payloads (anchor, flows, enrollment, step-up,
  WebAuthn ceremony, TOTP and recovery material, consent, logout index) are
  sealed with ChaCha20-Poly1305 under `storage.redis.encryption_secret`. A
  payload that does not open is deleted and the browser starts a fresh
  session.
- **Security:** the edge token cache stores the authority bearer token
  encrypted, deletes a rejected token by digest, and releases its refresh
  lock only by its owner.
- **Security:** secret configuration values render as `<hidden>` in every
  formatted and logged output. With debug logging, earlier v4 releases
  printed OIDC client secrets in the configuration they log at startup.
  **Action:** restrict or purge such debug logs and rotate the OIDC client
  secrets they contain.
- Browser sessions slide their idle expiry while in use: every opened session
  is extended to now plus 30 minutes, at most once per 5 minutes and never
  past the absolute expiry. Before, a session ended 30 minutes after login.
- **Behaviour change:** generated OIDC signing keys follow
  `identity.oidc.key_max_age` (default 7 days) instead of a 365-day fallback,
  and cleanup removes every inactive key older than that age. A
  `key_rotation_interval` that is not shorter than `key_max_age` is replaced
  by half the maximum age with a warning.
- **Behaviour change:** RFC 8414 authorization server metadata is served at
  `/.well-known/oauth-authorization-server`, and every redirect-based
  authorization response carries the RFC 9207 `iss` parameter. **Action:**
  route the new well-known path to Nauthilus and keep `identity.oidc.issuer`
  exactly as clients know it.
- `identity.oidc.hosted_resources` describes resources Nauthilus hosts itself
  (static clients only, a user right from `groups` or `group_dns`,
  `max_authentication_age`, and `max_access_token_lifetime`).
- `claims` of a custom scope is optional. For an enabled OIDC issuer the
  configuration load warns about a mapped claim no scope allowed for its
  client releases, a custom scope no client may request, and a client scope
  that is neither built in nor declared. **Action:** review the warnings
  after the upgrade; they never fail the load.
- The consent page shows translated texts for `nauthilus:history_read`,
  `nauthilus:history_detail`, and `nauthilus:operations_read` in all shipped
  locales.
- The admin user flush revokes OIDC tokens by backend account through the new
  `<prefix>oidc:account:{<account_slot>}:subjects` index, so tokens whose
  subject is the backend unique user ID no longer survive a flush. Tokens
  issued before the upgrade have no binding until their next refresh.
- SAML: a LogoutRequest listing several `SessionIndex` elements matches when
  any of them matches, HTTP-Redirect SLO messages are signed with `SigAlg`
  and `Signature` query parameters, SHA-1 AuthnRequest signatures are also
  rejected in the library validation path, and concurrent LogoutResponses of
  one fan-out transaction are applied atomically.

### Policy and post-actions

- An authn target can declare `terminal_post_actions`. They run once per
  answered request, whichever rule answered it, including built-in rejects
  such as ban hits. New metric
  `policy_terminal_post_actions_total{operation,post_action,result}`.
- Best-effort post-action plans are accepted only while fewer than half of
  `policy.runtime.post_actions.queue_capacity` is in flight; rejections count
  as `post_action_acceptance_failures_total{error_class="best_effort_saturated"}`
  and never fail a request.
- A Policy reload with an in-flight post-action no longer stalls for the
  cleanup budget, and a tempfail answered without a presenting rule names the
  failed checkpoint as its stage.

### ClickHouse plugin

- Login rows carry `contract_version = 1`, the sealed terminal outcome,
  `transport_status`, `flow_ref`, `brute_force_tolerated`, and
  `reputation_assessments`. Optional streams record step events and
  brute-force evidence. New host metric
  `plugin_auth_events_total{outcome,lane}`.
- **Behaviour change:** tempfails are recorded as `outcome=tempfail` with
  `http_status=500` and their tempfail text instead of a credential failure.
  Dashboards that filter on `status_msg='Invalid login or password'` stop
  counting them.
- **Behaviour change:** the 20 retired login columns (the flat `reputation_*`
  columns and the `gp_*`, `prot_*`, and `dyn_*` fields) are no longer
  exported. **Action:** update dashboards and queries; the bundled Grafana
  dashboard reads `reputation_assessments`.
- `max_brute_force_reject_rows` (default half of `max_buffer_rows`) reserves
  a share of the login buffer for brute-force rejects; excess rows are
  counted as `dropped_reject_limit`.

### Brute-force flushes, listings, and bundled Lua plugins

- **Behaviour change:** affected accounts age out per account after
  `auth.controls.brute_force.affected_accounts.retention` (default `24h`);
  `cleanup_enabled: false` keeps the previous behaviour. The leased
  background maintenance needs Redis 6.2 or newer.
- `POST /api/v1/bruteforce/list` accepts
  `"account_resolution": "account_mapping"` for 1 to 100 distinct accounts
  and returns per-name `resolutions`.
- **Behaviour change:** if the stored account mappings cannot be read,
  `/api/v1/cache/flush` answers `503 Account mapping lookup failed` before
  removing anything; automation must retry. The flush no longer removes
  mappings of other users whose login names start with `<name>|`.
- The user flush deletes the RWP window of every login identity behind the
  flushed accounts; before, windows survived until `rwp_window` expired.
- The bundled Lua plugins keep the keys of one Redis script on one hash tag,
  so Redis Cluster no longer separates writers from readers.
  `soft_delay.lua` and `dynamic_response.lua` read the per-protocol layouts
  the writers create, `haveibeenpwnd.lua` sends its leak notification again,
  and the `reset_account` admin hook clears the current keys of one account.

### Build and dependencies

- Server builds apply profile-guided optimization from `server/default.pgo`,
  which the release workflow refreshes from a dedicated authentication
  workload. Native plugins are built with the same profile.
- `github.com/twmb/franz-go` is pinned to v1.22.1 (`pkg/kmsg` v1.14.0) and
  `github.com/pierrec/lz4/v4` to v4.1.31, because lz4 v4.1.32 and later
  cannot be built with `-buildmode=plugin` on amd64. Out-of-tree plugins that
  share these modules must use the same versions.
- Dependency updates include `crewjam/saml` v0.6.3, OpenTelemetry v1.47.0,
  `quic-go` v0.65.0, `go-webauthn` v0.18.2, `go-oidc` v3.21.0, and the new
  official MCP Go SDK v1.8.0.
- `pluginapi/v1` gains the optional event sinks `AuthEventSink` and
  `BruteForceEventSink`, `PostActionRequest.Outcome` and `FactsTrimmed`,
  `IDPInfo.FlowRef`, `RequestDiagnostics.BruteForceTolerated`, and the
  exchange features `FeatureTLSEncryption` and `FeatureRelayDomains`.

### Brute-force toleration accounting and ban evidence

- **Behaviour change:** brute-force toleration works again. Since the Policy
  authority cutover before v4.0.0 no request recorded positive or negative
  toleration observations, so `tolerate_percent`, `custom_tolerations`, and
  the reputation-scaled bucket limits (including `adaptive_toleration`) had
  no effect on v4.x. Every authenticate request whose answer is backed by a
  host-verified credential outcome now records one observation for the client
  IP; tempfails, pre-auth rejections, identity lookups, and no-auth requests
  are not recorded. Networks with recent successful logins therefore get
  higher effective limits again, and over-limit buckets of tolerated networks
  are not banned. Review `tolerate_percent`, `min_tolerate_percent`,
  `max_tolerate_percent`, `adaptive_toleration`, and `custom_tolerations`
  before the upgrade.
- **Security fix:** toleration negatives now count every failed login attempt
  behind an address instead of distinct failing accounts. Before, valid logins
  of a few accounts kept an address tolerated while a single other account was
  attacked without limit, because all failures against one account counted
  once. Positives still count distinct accounts with a successful login.
  Repeating wrong passwords are not counted, like in the buckets. Shared
  addresses therefore reach the end of their toleration sooner; review
  `tolerate_percent`, `max_tolerate_percent`, and `tolerate_ttl` for proxies
  with many users.
- The toleration counters are counted on read from the `bf:tr:{<scoped ip>}:P`
  and `:N` sorted sets over exactly `tolerate_ttl`, so every instance sees the
  same exact values and recorded successes can no longer outlive the window.
  The `bf:tr:{<scoped ip>}` counter hash, the `CalculateAdaptiveToleration`
  and `ZAddCountAndExpire` scripts, and the per-instance toleration
  housekeeping are removed; idle sets expire with their key. Leftover counter
  hashes from earlier versions are no longer read and expire on their own.
- Toleration positives are keyed by the resolved account, so aliases of one
  mailbox no longer count as several accounts. A request that runs a second
  brute-force update (for example a custom `brute_force_update` obligation
  after a backend failure) is counted once and keeps its first repeating wrong
  password verdict.
- The brute-force and user flush endpoints now delete the real toleration
  sets (`bf:tr:{<scoped ip>}:P` and `:N`); they used to target keys without
  the cluster hash tag that were never written.
- Native plugins can register a `BruteForceEventSink`. The ClickHouse plugin
  writes ban activations, releases, counter resets, counted increments,
  tolerated thresholds, and ban hits to the new `bruteforce_lifecycle` and
  `bruteforce_attempts` tables. Apply
  `contrib/clickhouse-kubernetes/migrations/bruteforce-evidence.sql` before
  setting `bruteforce_lifecycle_insert_url` or
  `bruteforce_attempts_insert_url`. Bans created before the upgrade have no
  evidence rows; the export cannot reconstruct them.
- The `SlidingWindowCounter` Redis script returns two additional values
  (current and previous window counts). Mixed-version instances keep working:
  each version calls the script by the SHA of its own script text, so old and
  new replies never mix.
- A brute-force flush that fails after deleting some keys still reports the
  keys it removed.

## v4.0.9: Backend Tempfail Causes And Empty Credentials With Subject Providers

- A request the host settles without a backend result no longer fails the
  `subject_analysis` checkpoint when a subject provider is scheduled there
  with `run_if.auth_state` `any`, `unauthenticated`, or the default. The
  skipped provider (`backend_unavailable`) is now a regular skip, so the
  request reaches `auth_decision`:
  - An empty password or username answers `Invalid login or password`
    through `standard_empty_password` / `standard_empty_username` again.
    Before, it ended as a temporary failure with
    `tempfail_reason=policy_indeterminate checkpoint=subject_analysis
    status_code=provider_unavailable` and no other log line.
  - A backend temporary failure stays a temporary failure, now selected by
    `standard_backend_tempfail` with `outcome_marker=auth.outcome.backend_tempfail`.
- The terminal tempfail WARN line names a failed backend with
  `tempfail_reason=backend_tempfail`, lists the providers that had no
  backend result to analyze in `skipped_providers` (`instance:reason`), and
  carries the first technical error in `tempfail_error`, for example
  `backend_temporary_failure: plugin backend "mod.passdb" could not complete
  the request: plugin reported a temporary failure (user_lookup_failed)`.
  Log queries and alerts on `tempfail_reason=policy_indeterminate` no longer
  match backend outages.
- A native plugin backend failure names a bounded cause in the backend error:
  `plugin call failed (error|timeout|canceled|panic|admission_limited)`,
  `plugin reported a temporary failure (<Status.Code>): <Status.DefaultText>`,
  or an invalid result (`policy facts`, `account field`, `identity`). Raw
  plugin errors stay out of host logs; plugins should set `StatusMessage.Code`
  on temporary results and log their own error text with the request session.

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
