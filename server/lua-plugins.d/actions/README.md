# Action Plugins for Nauthilus

This directory contains Lua action plugins for the Nauthilus authentication system. Action plugins are executed in response to authentication events and can perform various tasks such as tracking failed logins, implementing dynamic security responses, and sending notifications.

## Available Plugins

### analytics.lua
A plugin that collects and analyzes authentication data for reporting and visualization purposes. It tracks successful and failed login attempts, user behavior patterns, and system usage statistics.

**Features:**
- Tracks authentication metrics by user, IP, and time
- Stores data in Redis for later analysis
- Supports data aggregation for reporting dashboards
- Provides insights into system usage patterns

**Usage:**
The plugin runs automatically on each authentication attempt. No manual configuration is required beyond enabling the plugin in your Nauthilus configuration.

### bruteforce.lua
Detects and mitigates brute force attacks by monitoring failed login attempts and implementing countermeasures when suspicious activity is detected.

**Features:**
- Tracks failed login attempts by IP address and username
- Implements progressive delays for repeated failed attempts
- Can temporarily block IPs with excessive failed attempts
- Logs detailed information about potential brute force attacks

**Usage:**
Configure the plugin through environment variables:
- `HAPROXY_STATS`: HAProxy stats socket endpoint
- `HAPROXY_SMTP_MAP`: HAProxy map file for SMTP protocol
- `HAPROXY_GENERIC_MAP`: HAProxy map file for other protocols

### dynamic_response.lua
Implements a sophisticated security response system that dynamically adjusts security measures based on detected threat levels.

**Features:**
- Calculates threat levels based on login patterns, geographic distribution, and other metrics
- Implements different security measures based on the threat level (severe, high, moderate, normal)
- Notifies administrators via email about security threats
- Uses Redis to store and track metrics, suspicious IPs, and regions
- Dynamically adjusts security settings like captcha requirements and rate limiting

**Usage:**
Configure the plugin through environment variables:
- `SMTP_*` variables for email notifications
- `ADMIN_EMAIL_ADDRESSES`: Comma-separated list of admin email addresses for notifications
- `CUSTOM_REDIS_POOL_NAME`: Optional custom Redis pool name

The plugin automatically calculates threat levels and applies appropriate security measures without manual intervention.

### failed_login_tracker.lua
Tracks failed login attempts for unrecognized accounts, maintaining a top-100 list of usernames with the most failed attempts.

**Features:**
- Tracks failed login attempts in a Redis sorted set
- Only tracks logins for unrecognized accounts (to avoid penalizing legitimate users who mistype passwords)
- Maintains a top-100 list of failed logins
- Provides logging and context information

**Usage:**
The plugin runs automatically on each authentication attempt. You can optionally configure a custom Redis pool using the `CUSTOM_REDIS_POOL_NAME` environment variable.

### haveibeenpwnd.lua
Checks user credentials against the "Have I Been Pwned" database to identify compromised passwords.

**Features:**
- Securely checks passwords against known data breaches
- Uses k-anonymity to protect user privacy during checks
- Alerts users and administrators about compromised credentials
- Integrates with the Nauthilus notification system

**Usage:**
Configure the plugin through environment variables:
- `CUSTOM_REDIS_POOL_NAME`: Optional custom Redis pool name
- `SMTP_*` variables: SMTP server configuration for sending notifications (SMTP_USE_LMTP, SMTP_SERVER, SMTP_PORT, SMTP_HELO_NAME, SMTP_TLS, SMTP_STARTTLS, SMTP_USERNAME, SMTP_PASSWORD, SMTP_MAIL_FROM)
- `SSP_WEBSITE`: URL to the self-service password change website

### telegram.lua
Sends security notifications and alerts to a Telegram channel or group.

**Features:**
- Sends real-time security alerts to Telegram
- Configurable notification levels (critical, warning, info)
- Supports rich text formatting for better readability
- Can include detailed metrics and threat information
- Since v1.8.2: Includes a password hash derived from the provided password when an account is present

**Behavior (v1.8.2):**
- The plugin only sends a Telegram message if `request.account` is set and non-empty.
- If a `request.password` is present, the plugin computes a short hash via the Go-backed Lua module `nauthilus_password.generate_password_hash(password)`.
  - This hash is identical to the one stored/used server-side for Redis password history: `util.GetHash(util.PreparePassword(password))`.
  - It uses the server's configured nonce internally and returns an 8-character lowercase hex string.
- The rendered Telegram message includes the field "PASSWORD HASH" along with other context.

**Usage:**
Configure the plugin through environment variables:
- `TELEGRAM_PASSWORD`: Your Telegram bot token/password
- `TELEGRAM_CHAT_ID`: The chat ID to send notifications to

**Compatibility Notes:**
- Requires Nauthilus v1.8.2+ for the `nauthilus_password.generate_password_hash` function to be available to Lua.
- The public documentation in the nauthilus_website repository should reflect these changes (v1.8.2).


### clickhouse.lua
Exports metrics about non-authenticated requests (including those without an existing account) to ClickHouse using batched inserts.

Features:
- Mirrors metrics/fields collected by telegram.lua, but does not require an existing account (account can be "n/a").
- Batches rows with the in-process nauthilus_cache to reduce HTTP insert overhead.
- Uses glua_http (cjoudrey/gluahttp) for HTTP POST to ClickHouse.

ClickHouse table schema (JSONEachRow):
```
CREATE TABLE IF NOT EXISTS nauthilus.logins (
  ts                   DateTime64(3, 'UTC'),
  session              String,
  service              LowCardinality(String) CODEC(ZSTD(3)),
  client_ip            String,
  client_port          String,
  client_net           LowCardinality(String),
  client_id            LowCardinality(String),
  hostname             LowCardinality(String) CODEC(ZSTD(3)),
  proto                LowCardinality(String),
  method               LowCardinality(String),
  user_agent           LowCardinality(String) CODEC(ZSTD(5)),
  local_ip             LowCardinality(String),
  local_port           String,
  display_name         LowCardinality(String),
  account              LowCardinality(String),
  account_field        LowCardinality(String),
  unique_user_id       LowCardinality(String),
  username             LowCardinality(String),
  password_hash        String,
  pwnd_info            LowCardinality(String),
  brute_force_bucket   LowCardinality(String),
  brute_force_counter  Nullable(UInt64),
  oidc_cid             LowCardinality(String),
  failed_login_count   Nullable(UInt64),
  failed_login_rank    Nullable(UInt64),
  failed_login_recognized Nullable(Bool),
  geoip_guid           LowCardinality(String),
  geoip_country        LowCardinality(String),
  geoip_iso_codes      LowCardinality(String),
  geoip_status         LowCardinality(String),
  gp_attempts          Nullable(UInt64),
  gp_unique_ips        Nullable(UInt64),
  gp_unique_users      Nullable(UInt64),
  gp_ips_per_user      Nullable(Float64),
  prot_active          Nullable(Bool),
  prot_reason          LowCardinality(String),
  prot_backoff         Nullable(UInt64),
  prot_delay_ms        Nullable(UInt64),
  dyn_threat           Nullable(UInt64),
  dyn_response         LowCardinality(String),
  debug                Nullable(Bool),
  repeating            Nullable(Bool),
  user_found           Nullable(Bool),
  authenticated        Nullable(Bool),
  no_auth              Nullable(Bool),
  xssl_protocol        LowCardinality(String),
  xssl_cipher          LowCardinality(String),
  ssl_fingerprint      LowCardinality(String),
  latency              UInt64,
  http_status          UInt16,
  status_msg           LowCardinality(String),
  INDEX idx_username   username   TYPE tokenbf_v1(1024, 3, 0) GRANULARITY 64,
  INDEX idx_account    account    TYPE tokenbf_v1(1024, 3, 0) GRANULARITY 64,
  INDEX idx_client_ip  client_ip  TYPE tokenbf_v1(1024, 3, 0) GRANULARITY 64
) ENGINE = MergeTree
ORDER BY (ts)
SETTINGS index_granularity = 8192;
```

Notes:
- ts is DateTime64(3, 'UTC'); other fields are String for schema stability. ClickHouse JSONEachRow will parse ISO-like timestamp strings for ts automatically.

Configuration (environment variables):
- CLICKHOUSE_INSERT_URL: Full HTTP endpoint including the INSERT and FORMAT JSONEachRow, e.g.
  http://clickhouse:8123/?query=INSERT%20INTO%20nauthilus.failed_logins%20FORMAT%20JSONEachRow
- CLICKHOUSE_USER / CLICKHOUSE_PASSWORD: Optional; sent via X-ClickHouse-User/Key headers.
- CLICKHOUSE_BATCH_SIZE: Optional batch size (default 100).
- CLICKHOUSE_CACHE_KEY: Optional cache key for batching list (default clickhouse:batch:failed_logins).

Batching details:
- The action pushes JSON-encoded rows via nauthilus_cache.cache_push(CLICKHOUSE_CACHE_KEY, row_json).
- When the heuristics suggest the threshold is reached, it flushes with nauthilus_cache.cache_pop_all and sends one NDJSON body (one JSON per line).
- On HTTP errors, rows are requeued best-effort with nauthilus_cache.cache_push.

Enabling the action:
- Ensure your post-actions configuration invokes server/lua-plugins.d/actions/clickhouse.lua after authentication processing.
