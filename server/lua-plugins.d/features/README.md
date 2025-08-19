# Feature Plugins for Nauthilus

This directory contains Lua feature plugins for the Nauthilus authentication system. Feature plugins extend the core functionality of Nauthilus by adding new capabilities, integrations, or advanced security features.

## Available Plugins

### blocklist.lua
Implements IP and username blocklisting functionality to prevent authentication attempts from known malicious sources.

**Features:**
- Checks authentication requests against configurable blocklists
- Supports IP address, IP range, and username blocklisting
- Integrates with external blocklist sources
- Provides automatic updates of blocklists
- Logs detailed information about blocked authentication attempts

**Usage:**
Configure the plugin through environment variables:
- `BLOCKLIST_URL`: URL of the blocklist service endpoint

You can also manually add entries to the blocklist using the Nauthilus API.

### global_pattern_monitoring.lua
Monitors global authentication patterns across the entire system to detect anomalies and potential security threats.

**Features:**
- Tracks authentication metrics in multiple time windows (1min, 5min, 15min, 1hour)
- Monitors unique IPs, unique usernames, and authentication attempts
- Calculates key metrics like attempts per IP, attempts per user, and IPs per user
- Stores current and historical metrics for trend analysis
- Provides detailed logging of global authentication patterns

**Usage:**
The plugin runs automatically on each authentication attempt. It stores metrics in Redis using keys with the prefix `ntc:multilayer:global:`. You can optionally configure a custom Redis pool using the `CUSTOM_REDIS_POOL_NAME` environment variable.

The metrics collected by this plugin are used by other components like the dynamic_response.lua action plugin to detect and respond to suspicious activity.

### failed_login_hotspot.lua
Derives a feature signal from the Redis ZSET `ntc:top_failed_logins` (maintained by actions/failed_login_tracker.lua). This plugin is read-only against Redis and enriches the runtime table (rt) so downstream actions can react.

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
  - Sets `rt.feature_failed_login_hotspot = true` and `rt.failed_login_hot = true` when the hotspot condition is met
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

**Configuration (nauthilus.yml):**
```yaml
lua:
  features:
    - name: "failed_login_hotspot"
      script_path: "/etc/nauthilus/lua-plugins.d/features/failed_login_hotspot.lua"
```

**Downstream integration:**
- actions/analytics.lua increments `analytics_count{feature="failed_login_hotspot"}` when the feature flag is present in rt.
- actions/telegram.lua sends a compact alert when `rt.feature_failed_login_hotspot` is set. It includes `failed_login_count` and `failed_login_rank` (if known) alongside the usual session/account context.

Note: This feature relies on the post-action `failed_login_tracker.lua` to maintain `ntc:top_failed_logins`. Ensure that action is enabled so the ZSET is populated.

### security_metrics.lua
Collects and exposes the security_* Prometheus metrics proposed in docs/attacker_detection_ideas.md. This feature is read-only and safe to run in learning mode. It reads per-account and global data from Redis and updates gauges/counters.

**Metrics updated:**
- `security_unique_ips_per_user{username,window}` (gauge; emission gated to avoid high cardinality)
- `security_account_fail_budget_used{username,window}` (gauge; emission gated to avoid high cardinality)
- `security_global_ips_per_user{window}` (gauge)
- `security_accounts_in_protection_mode_total` (gauge)
- `security_slow_attack_suspicions_total` (counter; heuristic)

Other related metrics are updated in companion plugins:
- `security_sprayed_password_tokens_total{window}` → features/account_longwindow_metrics.lua
- `security_stepup_challenges_issued_total` → filters/account_protection_mode.lua
- `security_pow_challenges_issued_total` → planned when PoW is implemented

**Cardinality controls (environment variables):**
- `SECURITY_METRICS_PER_USER_ENABLED` (default: false)
  - When false, per-user security_* metrics are not emitted (no time series per username).
  - When true, per-user metrics are emitted for protected users and/or sampled users (see below). If `SECURITY_METRICS_SAMPLE_RATE` is unset, it defaults to 100% (1.0) so you immediately see per-user metrics. Set the sample rate explicitly to control cardinality.
- `SECURITY_METRICS_SAMPLE_RATE` (default: unset → treated as 1.0 when per-user metrics are enabled)
  - Float 0.0–1.0. Deterministic sampling by username hash. For example, 0.01 ≈ 1% of users. Set to `0` to disable per-user emission except for users currently in protection mode.
  - Users currently in protection mode are always emitted regardless of the sample rate.

Protected users are tracked in Redis set `ntc:acct:protection_active` (maintained by filters/account_protection_mode.lua).

**Requirements:**
- Global windows (24h/7d) provided by features/global_pattern_monitoring.lua
- Per‑account long‑window data provided by features/account_longwindow_metrics.lua

**Usage:**
The plugin runs on each authentication attempt and updates Prometheus metrics. Optionally use a custom Redis pool via `CUSTOM_REDIS_POOL_NAME`.

**Configuration (nauthilus.yml):**
```yaml
lua:
  features:
    - name: "security_metrics"
      script_path: "/etc/nauthilus/lua-plugins.d/features/security_metrics.lua"
```
