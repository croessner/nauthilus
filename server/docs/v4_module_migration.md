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
