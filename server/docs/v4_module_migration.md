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
