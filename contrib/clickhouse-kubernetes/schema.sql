-- Nauthilus ClickHouse schema for Kubernetes deployments
-- Creates database and table used by server/lua-plugins.d/actions/clickhouse.lua
-- All fields are String for schema stability; cast at query time if needed.

CREATE DATABASE IF NOT EXISTS nauthilus;

CREATE TABLE IF NOT EXISTS nauthilus.failed_logins (
  ts                 String,
  session            String,
  client_ip          String,
  hostname           String,
  proto              String,
  display_name       String,
  account            String,
  unique_user_id     String,
  username           String,
  password_hash      String,
  pwnd_info          String,
  brute_force_bucket String,
  failed_login_count String,
  failed_login_rank  String,
  failed_login_recognized String,
  geoip_guid         String,
  geoip_country      String,
  geoip_iso_codes    String,
  geoip_status       String,
  gp_attempts        String,
  gp_unique_ips      String,
  gp_unique_users    String,
  gp_ips_per_user    String,
  prot_active        String,
  prot_reason        String,
  prot_backoff       String,
  prot_delay_ms      String,
  dyn_threat         String,
  dyn_response       String
) ENGINE = MergeTree
ORDER BY (ts)
SETTINGS index_granularity = 8192;
