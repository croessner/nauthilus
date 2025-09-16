-- Nauthilus ClickHouse schema for Kubernetes deployments
-- Creates database and table used by server/lua-plugins.d/actions/clickhouse.lua
-- ts uses DateTime64(3, 'UTC') for precise timestamps.
-- Most textual columns with repeating values are LowCardinality(String) to deduplicate values efficiently.
-- For existing installations (legacy), see the ALTER TABLE block at the end of this file.

CREATE DATABASE IF NOT EXISTS nauthilus;

CREATE TABLE IF NOT EXISTS nauthilus.logins (
  ts                   DateTime64(3, 'UTC'),
  session              String, -- high cardinality; keep as plain String
  service              LowCardinality(String) CODEC(ZSTD(3)),
  features             LowCardinality(String) CODEC(ZSTD(3)),
  client_ip            String, -- could be IPv4/IPv6; left as String for compatibility
  client_port          String,
  client_net           LowCardinality(String),
  client_id            LowCardinality(String),
  hostname             LowCardinality(String) CODEC(ZSTD(3)),
  proto                LowCardinality(String),
  user_agent           LowCardinality(String) CODEC(ZSTD(5)),
  local_ip             LowCardinality(String),
  local_port           String,
  display_name         LowCardinality(String),
  account              LowCardinality(String),
  account_field        LowCardinality(String),
  unique_user_id       LowCardinality(String),
  username             LowCardinality(String),
  password_hash        String, -- may already be compressed effectively; keep as String
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
  INDEX idx_username   username   TYPE tokenbf_v1(1024, 3, 0) GRANULARITY 64,
  INDEX idx_account    account    TYPE tokenbf_v1(1024, 3, 0) GRANULARITY 64,
  INDEX idx_client_ip  client_ip  TYPE tokenbf_v1(1024, 3, 0) GRANULARITY 64
) ENGINE = MergeTree
ORDER BY (ts)
SETTINGS index_granularity = 8192;

/*
Legacy upgrade guide (run online, one by one). Safe to repeat.

ALTER TABLE nauthilus.logins MODIFY COLUMN service            LowCardinality(String) CODEC(ZSTD(3));
ALTER TABLE nauthilus.logins MODIFY COLUMN features           LowCardinality(String) CODEC(ZSTD(3));
ALTER TABLE nauthilus.logins MODIFY COLUMN client_net         LowCardinality(String);
ALTER TABLE nauthilus.logins MODIFY COLUMN client_id          LowCardinality(String);
ALTER TABLE nauthilus.logins MODIFY COLUMN hostname           LowCardinality(String) CODEC(ZSTD(3));
ALTER TABLE nauthilus.logins MODIFY COLUMN proto              LowCardinality(String);
ALTER TABLE nauthilus.logins MODIFY COLUMN user_agent         LowCardinality(String) CODEC(ZSTD(5));
ALTER TABLE nauthilus.logins MODIFY COLUMN local_ip           LowCardinality(String);
ALTER TABLE nauthilus.logins MODIFY COLUMN display_name       LowCardinality(String);
ALTER TABLE nauthilus.logins MODIFY COLUMN account            LowCardinality(String);
ALTER TABLE nauthilus.logins MODIFY COLUMN account_field      LowCardinality(String);
ALTER TABLE nauthilus.logins MODIFY COLUMN unique_user_id     LowCardinality(String);
ALTER TABLE nauthilus.logins MODIFY COLUMN username           LowCardinality(String);
ALTER TABLE nauthilus.logins MODIFY COLUMN pwnd_info          LowCardinality(String);
ALTER TABLE nauthilus.logins MODIFY COLUMN brute_force_bucket LowCardinality(String);
ALTER TABLE nauthilus.logins MODIFY COLUMN oidc_cid           LowCardinality(String);
ALTER TABLE nauthilus.logins MODIFY COLUMN geoip_guid         LowCardinality(String);
ALTER TABLE nauthilus.logins MODIFY COLUMN geoip_country      LowCardinality(String);
ALTER TABLE nauthilus.logins MODIFY COLUMN geoip_iso_codes    LowCardinality(String);
ALTER TABLE nauthilus.logins MODIFY COLUMN geoip_status       LowCardinality(String);
ALTER TABLE nauthilus.logins MODIFY COLUMN prot_reason        LowCardinality(String);
ALTER TABLE nauthilus.logins MODIFY COLUMN dyn_response       LowCardinality(String);
ALTER TABLE nauthilus.logins MODIFY COLUMN xssl_protocol      LowCardinality(String);
ALTER TABLE nauthilus.logins MODIFY COLUMN xssl_cipher        LowCardinality(String);
ALTER TABLE nauthilus.logins MODIFY COLUMN ssl_fingerprint    LowCardinality(String);

-- Notes:
-- - These ALTERs trigger background mutation and re-encoding of affected parts.
-- - Keep session, client_ip, client_port, local_port, password_hash as-is due to likely high cardinality or specific semantics.
-- - You can adjust ZSTD level to taste; 3–5 is a practical range for UA/hostname.
*/
