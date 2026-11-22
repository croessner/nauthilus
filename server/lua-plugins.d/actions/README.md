# Action Plugins for Nauthilus

This directory contains Lua action plugins for the Nauthilus authentication system. Action plugins are executed in response to authentication events and can perform various tasks such as tracking failed logins, implementing dynamic security responses, and sending notifications.

## Policy Integration

Action plugins run after the decision-relevant checks. They must not create a second authority path; use them for
obligations, notifications, metrics, and response follow-up. When a preceding environment or subject source stored
`policy_facts`, actions can read them with `nauthilus_context.context_get("policy_facts")` and include selected
public facts in notifications or reports.

These action callbacks, including the existing post-action path, remain authentication-specific behavior and are
explicitly configured in the `authn` namespace. Their callback names and execution order are not used by generic
targets.

Generic `kind: lua` providers use the separate `_G["policy.effects.execute"]` callback documented in
[`../policy/README.md`](../policy/). It is invoked only for a policy-selected, target-allowed, schema-valid
`host_sync` or `host_post_action` obligation. Advice and `return_only` effects never invoke Lua. A generic post-action is
captured and accepted by the host supervisor before response finalization; the script receives no finalization gate and
must not launch detached host work. The host makes no automatic retry and preserves `outcome_unknown` as an observable,
non-retryable result.

## Bundled callback status

Every action in this directory can be configured as a `lua_action` effect; `test_context_chain.lua` is test-only.
Actions run with the complete Lua API, including Redis and cache writes, outbound HTTP, TCP, and mail. A synchronous
action can set HTTP response headers. A POST-Action runs after the response left the server, so its
`nauthilus_http_response` calls have no effect. The bundled native plugins `authn/plugin.clickhouse.post_action` and
`authn/plugin.haveibeenpwnd.post_action` are maintained alternatives to `clickhouse.lua` and `haveibeenpwnd.lua`. The
per-file status is in [`../POLICY_VM_COMPATIBILITY.md`](../POLICY_VM_COMPATIBILITY.md).

The checked-in synchronous response-action configuration is
[`../examples/policy-safe-bruteforce-header.yml`](../examples/policy-safe-bruteforce-header.yml).

## Available Plugins

### analytics.lua
A plugin that collects and analyzes authentication data for reporting and visualization purposes. It tracks successful and failed login attempts, user behavior patterns, and system usage statistics.

**Capabilities:**
- Tracks authentication metrics by user, IP, and time
- Stores data in Redis for later analysis
- Supports data aggregation for reporting dashboards
- Provides insights into system usage patterns

### bruteforce.lua
Detects and mitigates brute force attacks by monitoring failed login attempts and implementing countermeasures when suspicious activity is detected.

**Capabilities:**
- Tracks failed login attempts by IP address and username
- Implements progressive delays for repeated failed attempts
- Can temporarily block IPs with excessive failed attempts
- Logs detailed information about potential brute force attacks

**Configuration:**
The callback reads the following environment variables:
- `HAPROXY_STATS`: HAProxy stats socket endpoint
- `HAPROXY_SMTP_MAP`: HAProxy map file for SMTP protocol
- `HAPROXY_GENERIC_MAP`: HAProxy map file for other protocols

### dynamic_response.lua
Implements a sophisticated security response system that dynamically adjusts security measures based on detected threat levels.

**Capabilities:**
- Calculates threat levels based on login patterns, geographic distribution, and other metrics
- Implements different security measures based on the threat level (severe, high, moderate, normal)
- Notifies administrators via email about security threats
- Uses Redis to store and track metrics, suspicious IPs, and regions
- Dynamically adjusts security settings like captcha requirements and rate limiting

**Configuration:**
The callback reads the following environment variables:
- `SMTP_*` variables for email notifications
- `ADMIN_EMAIL_ADDRESSES`: Comma-separated list of admin email addresses for notifications
- `CUSTOM_REDIS_POOL_NAME`: Optional custom Redis pool name

The callback calculates threat levels and applies security measures without manual intervention.

### failed_login_tracker.lua
Tracks failed login attempts for unrecognized accounts, maintaining a top-100 list of usernames with the most failed attempts.

**Capabilities:**
- Tracks failed login attempts in a Redis sorted set
- Only tracks logins for unrecognized accounts (to avoid penalizing legitimate users who mistype passwords)
- Maintains a top-100 list of failed logins
- Provides logging and context information

### haveibeenpwnd.lua
Checks user credentials against the "Have I Been Pwned" database to identify compromised passwords.

Native alternative: configure the bundled Go plugin `haveibeenpwnd` and reference the native policy effect ID
`authn/plugin.haveibeenpwnd.post_action`. The native plugin keeps the k-anonymity HTTP, Redis gate, cache behavior, and SMTP/LMTP
mail notification through `Host.Mail("haveibeenpwnd")`. Enable mail in `plugins.modules[].config.mail` and add the
`mail` capability beside `credentials` before restart. Both claim the notification once through the `send_mail`
hash field: this action through the `nauthilus_send_mail_hash` script that `init/init.lua` uploads, the native plugin
through a direct Redis `HSETNX`.

**Capabilities:**
- Securely checks passwords against known data breaches
- Uses k-anonymity to protect user privacy during checks
- Alerts users and administrators about compromised credentials
- Integrates with the Nauthilus notification system

**Lua configuration:**
The Lua callback reads the following environment variables; the native plugin uses typed module config:
- `CUSTOM_REDIS_POOL_NAME`: Optional custom Redis pool name
- `SMTP_*` variables: SMTP server configuration for sending notifications (SMTP_USE_LMTP, SMTP_SERVER, SMTP_PORT, SMTP_HELO_NAME, SMTP_TLS, SMTP_STARTTLS, SMTP_USERNAME, SMTP_PASSWORD, SMTP_MAIL_FROM)
- `SSP_WEBSITE`: URL to the self-service password change website

### telegram.lua
Sends security notifications and alerts to a Telegram channel or group.

**Capabilities:**
- Sends real-time security alerts to Telegram
- Configurable notification levels (critical, warning, info)
- Supports rich text formatting for better readability
- Can include detailed metrics and threat information
- Since v1.8.2: Includes a password hash derived from the provided password when an account is present

**Behavior (v1.8.2):**
- The plugin only sends a Telegram message if `request.account` is set and non-empty.
- If a `request.password` is present, the plugin computes a full hash via the Go-backed Lua module `nauthilus_password.generate_password_hash(password)`.
  - This hash is identical to `util.GetHashBytes` applied to bytes returned by `util.PreparePasswordBytesWithConfig` with the request-captured configuration.
  - It uses the server's configured nonce internally and returns a 64-character lowercase SHA-256 hex string.
- The rendered Telegram message includes the field "PASSWORD HASH" along with other context.

**Configuration:**
The callback reads the following credentials from environment variables:
- `TELEGRAM_PASSWORD`: Your Telegram bot token/password
- `TELEGRAM_CHAT_ID`: The chat ID to send notifications to

**Compatibility Notes:**
- Requires Nauthilus v1.8.2+ for the `nauthilus_password.generate_password_hash` function to be available to Lua.
- The public documentation in the nauthilus_website repository should reflect these changes (v1.8.2).


### clickhouse.lua
Exports metrics about non-authenticated requests (including those without an existing account) to ClickHouse using batched inserts.

Native alternative: configure the bundled Go plugin `clickhouse` and reference the native policy effect ID
`authn/plugin.clickhouse.post_action`. The native plugin writes the same JSONEachRow field names through host-managed HTTP, Redis, and
cache facades, except the retired flat `reputation_*`, `gp_*`, `prot_*`, and `dyn_*` fields, which no producer fills any
more. The Lua script still sends them, so it only works with tables that keep those columns: fresh tables from
`contrib/clickhouse-kubernetes/schema.sql` no longer have them, and its retirement block drops them from existing tables. Native post-actions cannot apply runtime deltas, so the Lua `rt.post_clickhouse = true` marker is not
mutated back into request runtime state.

Capabilities:
- Mirrors metrics/fields collected by telegram.lua, but does not require an existing account (account can be "n/a").
- Batches rows with the in-process nauthilus_cache to reduce HTTP insert overhead.
- Uses glua_http (cjoudrey/gluahttp) for HTTP POST to ClickHouse.
- Validates the general 64-character password hash and exports its first eight lowercase hex characters only in the ClickHouse row.

ClickHouse table schema expected by this retired script (JSONEachRow). It still contains the retired legacy columns;
do not copy it for new installations, use `contrib/clickhouse-kubernetes/schema.sql` instead:
```
CREATE TABLE IF NOT EXISTS nauthilus.logins (
  ts                   DateTime64(3, 'UTC'),
  session              String,
  service              LowCardinality(String) CODEC(ZSTD(3)),
  decision_sources     String,
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
  geoip_source         LowCardinality(String),
  geoip_matched        Nullable(Bool),
  geoip_country_name   LowCardinality(String),
  geoip_city_name      LowCardinality(String),
  geoip_asn            Nullable(UInt64),
  geoip_asn_org        LowCardinality(String),
  geoip_asn_prefix     LowCardinality(String),
  geoip_asn_registry   LowCardinality(String),
  geoip_asn_country    LowCardinality(String),
  geoip_asn_allocated  LowCardinality(String),
  geoip_asn_status     LowCardinality(String),
  reputation_score             Nullable(Float64),
  reputation_positive_score    Nullable(Float64),
  reputation_negative_score    Nullable(Float64),
  reputation_ip_score          Nullable(Float64),
  reputation_asn_score         Nullable(Float64),
  reputation_country_score     Nullable(Float64),
  reputation_asn_country_score Nullable(Float64),
  reputation_samples           Nullable(UInt64),
  reputation_source            LowCardinality(String),
  reputation_decision          LowCardinality(String),
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

Lua configuration (environment variables):
- CLICKHOUSE_INSERT_URL: Full HTTP endpoint including the INSERT and FORMAT JSONEachRow, e.g.
  http://clickhouse:8123/?query=INSERT%20INTO%20nauthilus.logins%20FORMAT%20JSONEachRow
- CLICKHOUSE_USER / CLICKHOUSE_PASSWORD: Optional; sent via X-ClickHouse-User/Key headers.
- CLICKHOUSE_BATCH_SIZE: Optional batch size (default 100).
- CLICKHOUSE_CACHE_KEY: Optional cache key for batching list (default clickhouse:batch:logins).

Batching details:
- The action pushes JSON-encoded rows via nauthilus_cache.cache_push(CLICKHOUSE_CACHE_KEY, row_json).
- When the heuristics suggest the threshold is reached, it flushes with nauthilus_cache.cache_pop_all and sends one NDJSON body (one JSON per line).
- On HTTP errors, rows are requeued best-effort with nauthilus_cache.cache_push.

Production activation:
- Do not configure `actions/clickhouse.lua` as a Policy action.
- Use policy obligations with `id: authn/plugin.clickhouse.post_action` after configuring the native module.
