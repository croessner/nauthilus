# Lua Environment Source Plugins for Nauthilus

This directory contains Lua environment source plugins for the Nauthilus authentication system. They collect pre-authentication signals and can trigger environment-derived decisions.

## Policy Integration

Configure a compatible custom script below `policy.namespaces.authn.providers.lua_environment_<name>` with
`kind: lua_environment`. A provider instance below the owning domain plan selects the exact
`authn/lua_environment_<name>` identity with `use`; its local `name` controls scheduling and its `after` dependencies.
The decision layer records
`auth.lua.environment.<name>.triggered`, `auth.lua.environment.<name>.abort`, and `auth.lua.environment.<name>.error`.

Scripts that collect supporting signals can emit Lua-owned attributes through `nauthilus_policy_facts`. The bundled
environment source attributes are registered by `../policy/registry.lua` and use IDs below `lua.plugin.*`, for example
`lua.plugin.blocklist.matched` or `lua.plugin.failed_login_hotspot.triggered`. The same values remain available under
`policy_facts` for later actions.

This environment-source contract is authentication-specific behavior. It is explicitly bound to `authn`, retains its
established callback name and ordering, and never runs for a generic target. Generic Lua fact
providers use the separate `_G["policy.facts.collect"]` contract documented in [`../policy/README.md`](../policy/).

## Bundled callback status

None of the operational examples in this directory is currently a supported production Policy callback: they require
Redis writes/scripts/pipelines, outbound HTTP, or ambient tuning values. `test_context_chain.lua` is test-only. See the
normative [`../POLICY_VM_COMPATIBILITY.md`](../POLICY_VM_COMPATIBILITY.md) table before authoring configuration. The
descriptions below document historical behavior and migration intent, not activation instructions.

## Available Plugins

### blocklist.lua
Implements IP and username blocklisting functionality to prevent authentication attempts from known malicious sources.

**Capabilities:**
- Checks authentication requests against configurable blocklists
- Supports IP address, IP range, and username blocklisting
- Integrates with external blocklist sources
- Provides automatic updates of blocklists
- Logs detailed information about blocked authentication attempts

**Historical configuration:**
This reference-only callback used the following environment variable outside the Policy VM:
- `BLOCKLIST_URL`: URL of the blocklist service endpoint

You can also manually add entries to the blocklist using the Nauthilus API.

### global_pattern_monitoring.lua
Monitors global authentication patterns across the entire system to detect anomalies and potential security threats.

**Capabilities:**
- Tracks authentication metrics in multiple time windows (1min, 5min, 15min, 1hour)
- Monitors unique IPs, unique usernames, and authentication attempts
- Calculates key metrics like attempts per IP, attempts per user, and IPs per user
- Stores current and historical metrics for trend analysis
- Provides detailed logging of global authentication patterns

**Usage:**
The historical callback stored metrics in Redis using keys with the prefix `ntc:multilayer:global:` and optionally
selected a custom Redis pool. Top-level Policy candidate preparation rejects those write and ambient-pool capabilities.

The metrics collected by this plugin are used by other components like the dynamic_response.lua action plugin to detect and respond to suspicious activity.

### failed_login_hotspot.lua
Derives an environment signal from the Redis ZSET `ntc:top_failed_logins` (maintained by
`actions/failed_login_tracker.lua`). Most lookups are reads, but the callback also writes a Redis snapshot gate and
enriches the legacy runtime table for downstream actions.

**What it does:**
- Looks up the current failed-login count (ZSCORE) and rank (ZREVRANK) for the request.username
- Exposes Prometheus metrics:
  - `failed_login_hotspot_user_score{username=...}` (gauge)
  - `failed_login_hotspot_user_rank{username=...}` (gauge, when rank is known)
  - `failed_login_hotspot_top_score{rank=...,username=...}` (gauge for a small Top‑N snapshot)
  - `failed_login_hotspot_topn_size` (gauge)
  - `failed_login_hotspot_count{state="hot"}` (counter, increments when hotspot triggers)
- Enriches the result table (rt):
  - `rt.failed_login_info = { username, new_count, rank, recognized_account }`
  - Sets `rt.environment_failed_login_hotspot = true` and `rt.failed_login_hot = true` when the hotspot condition is met
- Adds custom logs for correlation: `failed_login_username`, `failed_login_count`, `failed_login_rank`

**Hotspot condition (defaults, configurable):**
- Username score >= `FAILED_LOGIN_HOT_THRESHOLD` (default: 10)
- And the username is within Top‑K by rank (`FAILED_LOGIN_TOP_K`, default: 20). If rank is not available (e.g., trimmed), the threshold alone can mark it as hot.

**Environment variables:**
- `FAILED_LOGIN_HOT_THRESHOLD` (number, default: 10)
- `FAILED_LOGIN_TOP_K` (number, default: 20)
- `FAILED_LOGIN_SNAPSHOT_SEC` (number, default: 30) – rate-limit for the Top‑N snapshot
- `FAILED_LOGIN_SNAPSHOT_TOPN` (number, default: 10) – how many top usernames to snapshot
- `CUSTOM_REDIS_POOL_NAME` (optional) – use a non-default Redis pool

**Production status:** Reference-only. Its Redis snapshot gate writes state and its thresholds come from ambient
environment variables, so it must not be configured as a top-level Policy provider.

**Downstream integration:**
- actions/analytics.lua increments `analytics_count{environment="failed_login_hotspot"}` when the environment flag is present in rt.
- actions/telegram.lua sends a compact alert when `rt.environment_failed_login_hotspot` is set. It includes `failed_login_count` and `failed_login_rank` (if known) alongside the usual session/account context.

The historical environment source relied on the reference-only `failed_login_tracker.lua` action to maintain
`ntc:top_failed_logins`; there is no supported production pairing under the Policy VM.

### security_metrics.lua
Historically collected the `security_*` Prometheus metrics proposed in `docs/attacker_detection_ideas.md`. It reads
per-account and global Redis data, uses a Redis pipeline, and updates host-created gauges and counters; it is not a
supported Policy VM learning-mode callback.

**Metrics updated:**
- `security_unique_ips_per_user{username,window}` (gauge; emission gated to avoid high cardinality)
- `security_account_fail_budget_used{username,window}` (gauge; emission gated to avoid high cardinality)
- `security_global_ips_per_user{window}` (gauge)
- `security_accounts_in_protection_mode_total` (gauge)
- `security_slow_attack_suspicions_total` (counter; heuristic)

Other related metrics are updated in companion plugins:
- `security_sprayed_password_tokens_total{window}` -> environment/account_longwindow_metrics.lua
- `security_stepup_challenges_issued_total` -> subject/account_protection_mode.lua
- `security_pow_challenges_issued_total` → planned when PoW is implemented

**Cardinality controls (environment variables):**
- `SECURITY_METRICS_PER_USER_ENABLED` (default: false)
  - When false, per-user security_* metrics are not emitted (no time series per username).
  - When true, per-user metrics are emitted for protected users and/or sampled users (see below). If `SECURITY_METRICS_SAMPLE_RATE` is unset, it defaults to 100% (1.0) so you immediately see per-user metrics. Set the sample rate explicitly to control cardinality.
- `SECURITY_METRICS_SAMPLE_RATE` (default: unset → treated as 1.0 when per-user metrics are enabled)
  - Float 0.0–1.0. Deterministic sampling by username hash. For example, 0.01 ≈ 1% of users. Set to `0` to disable per-user emission except for users currently in protection mode.
  - Users currently in protection mode are always emitted regardless of the sample rate.

Protected users are tracked in Redis set `ntc:acct:protection_active:proto:<protocol>` (maintained by
subject/account_protection_mode.lua) and are protocol-scoped.

**Requirements:**
- Global windows (24h/7d) provided by environment/global_pattern_monitoring.lua
- Per-account long-window data provided by environment/account_longwindow_metrics.lua

**Production status:** Reference-only. The callback requires a Redis pipeline and ambient cardinality/pool values,
which candidate preparation does not expose.
