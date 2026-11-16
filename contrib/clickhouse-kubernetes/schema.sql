-- Nauthilus ClickHouse schema for Kubernetes deployments
-- Creates the database and table consumed by authn/plugin.clickhouse.post_action.
-- ts uses DateTime64(3, 'UTC') for precise timestamps.
-- Most textual columns with repeating values are LowCardinality(String) to deduplicate values efficiently.
-- For existing installations, apply migrations/diagnostic-contract.sql and see the ALTER TABLE block at the end.
-- The diagnostic data contract (outcome, events, versions, NULL semantics) is contrib/plugins/clickhouse/DIAGNOSTIC_CONTRACT.md.

CREATE DATABASE IF NOT EXISTS nauthilus;

CREATE TABLE IF NOT EXISTS nauthilus.logins (
  ts                   DateTime64(3, 'UTC'),
  session              String, -- high cardinality; keep as plain String
  service              LowCardinality(String) CODEC(ZSTD(3)),
  deployment           LowCardinality(String) DEFAULT '' CODEC(ZSTD(3)),
  instance             LowCardinality(String) DEFAULT '' CODEC(ZSTD(3)),
  decision_sources     LowCardinality(String) CODEC(ZSTD(3)),
  rbl_lists            Array(LowCardinality(String)),
  client_ip            String, -- could be IPv4/IPv6; left as String for compatibility
  client_port          String,
  client_net           LowCardinality(String),
  client_id            LowCardinality(String),
  hostname             LowCardinality(String) CODEC(ZSTD(3)),
  proto                LowCardinality(String),
  method         LowCardinality(String),
  user_agent           LowCardinality(String) CODEC(ZSTD(5)),
  local_ip             LowCardinality(String),
  local_port           String,
  display_name         LowCardinality(String),
  account              LowCardinality(String),
  username             LowCardinality(String),
  password_hash        String, -- may already be compressed effectively; keep as String
  pwnd_info            LowCardinality(String),
  brute_force_bucket   LowCardinality(String),
  brute_force_counter  Nullable(UInt64),
  oidc_cid             LowCardinality(String),
  saml_entity_id LowCardinality(String),
  grant_type     LowCardinality(String),
  mfa_method     LowCardinality(String),
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
  geoip_privacy_lookup_state LowCardinality(String),
  geoip_privacy_detected Nullable(Bool),
  geoip_privacy_classes Array(String),
  geoip_privacy_primary_class LowCardinality(String),
  geoip_privacy_confidence Nullable(Float64),
  geoip_privacy_source_authorities Array(String),
  geoip_privacy_data_stale Nullable(Bool),
  geoip_privacy_data_age_seconds Nullable(UInt64),
  geoip_is_tor_exit_node Nullable(Bool),
  geoip_is_known_vpn_exit Nullable(Bool),
  geoip_is_community_vpn_exit Nullable(Bool),
  geoip_is_public_proxy Nullable(Bool),
  geoip_is_privacy_relay Nullable(Bool),
  geoip_is_hosting_network Nullable(Bool),
  geoip_is_shared_egress Nullable(Bool),
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
  repeating            Nullable(Bool),
  rwp Nullable(Bool),
  user_found           Nullable(Bool),
  authenticated        Nullable(Bool),
  xssl_protocol        LowCardinality(String),
  xssl_cipher          LowCardinality(String),
  ssl_fingerprint      LowCardinality(String),
  latency        UInt64,
  http_status    UInt16,
  status_msg     LowCardinality(String),
  contract_version     UInt16 DEFAULT 0, -- 0 legacy row, 1 diagnostic data contract
  event_id             String DEFAULT '',
  operation            LowCardinality(String) DEFAULT '',
  outcome              LowCardinality(String) DEFAULT '', -- ok, fail, tempfail, unknown; empty for legacy rows
  outcome_stage        LowCardinality(String) DEFAULT '',
  outcome_marker       LowCardinality(String) DEFAULT '',
  response_marker      LowCardinality(String) DEFAULT '',
  policy_rule          LowCardinality(String) DEFAULT '',
  tempfail_reason      LowCardinality(String) DEFAULT '',
  tempfail_checkpoint  LowCardinality(String) DEFAULT '',
  policy_status        LowCardinality(String) DEFAULT '',
  fsm_state            LowCardinality(String) DEFAULT '',
  transport            LowCardinality(String) DEFAULT '',
  transport_status     Nullable(UInt16), -- committed HTTP status; NULL for gRPC or unknown
  flow_ref             String DEFAULT '', -- non-authorizing IdP flow digest
  brute_force_tolerated Nullable(Bool),
  reputation_assessments Array(Tuple(
    fact LowCardinality(String), role LowCardinality(String), kind LowCardinality(String),
    state LowCardinality(String), profile LowCardinality(String), band LowCardinality(String),
    override LowCardinality(String), risk_score Nullable(Float64), trust_score Nullable(Float64),
    confidence Nullable(Float64), samples Nullable(Float64), source_diversity Nullable(Int64),
    age_seconds Nullable(Int64))),
  reputation_truncated Bool DEFAULT false,
  INDEX idx_flow_ref   flow_ref   TYPE bloom_filter GRANULARITY 64,
  INDEX idx_username   username   TYPE tokenbf_v1(1024, 3, 0) GRANULARITY 64,
  INDEX idx_account    account    TYPE tokenbf_v1(1024, 3, 0) GRANULARITY 64,
  INDEX idx_client_ip  client_ip  TYPE tokenbf_v1(1024, 3, 0) GRANULARITY 64
) ENGINE = MergeTree
ORDER BY (ts)
TTL ts + INTERVAL 1 WEEK DELETE
SETTINGS index_granularity = 8192;

-- Second-factor and other host step events (DIAGNOSTIC_CONTRACT.md section 7); never a copy of login rows.
CREATE TABLE IF NOT EXISTS nauthilus.auth_events (
  ts             DateTime64(3, 'UTC'),
  event_id       String,
  event_type     LowCardinality(String),
  event_version  UInt16,
  deployment     LowCardinality(String),
  instance       LowCardinality(String),
  request_id     String,
  flow_ref       String,
  protocol       LowCardinality(String),
  client_id      LowCardinality(String),
  saml_entity_id LowCardinality(String),
  account        LowCardinality(String),
  client_ip      String,
  factor_role    LowCardinality(String),
  method         LowCardinality(String),
  result         LowCardinality(String),
  reason         LowCardinality(String),
  flow_effect    LowCardinality(String),
  fail_latched   Bool,
  INDEX idx_events_flow_ref flow_ref TYPE bloom_filter GRANULARITY 64,
  INDEX idx_events_account  account  TYPE tokenbf_v1(1024, 3, 0) GRANULARITY 64
) ENGINE = ReplacingMergeTree
ORDER BY (event_type, ts, event_id)
TTL toDateTime(ts) + INTERVAL 1 WEEK DELETE
SETTINGS index_granularity = 8192;

-- Brute-force evidence (DIAGNOSTIC_CONTRACT.md section 13); existing installations apply migrations/bruteforce-evidence.sql.
-- Rare ban lifecycle transitions; no claimed login names and no client address (the activating request can be an
-- uninvolved user behind the same network); long retention for ban explanations.
CREATE TABLE IF NOT EXISTS nauthilus.bruteforce_lifecycle (
  ts                   DateTime64(3, 'UTC'),
  event_id             String,
  event_version        UInt16,
  kind                 LowCardinality(String),
  deployment           LowCardinality(String),
  instance             LowCardinality(String),
  request_id           String,
  network              String,
  ip_family            UInt8,
  cidr                 UInt8,
  rule                 LowCardinality(String),
  rule_fingerprint     LowCardinality(String),
  stored_rule          LowCardinality(String),
  bucket_id            String,
  period_seconds       Int64,
  ban_time_seconds     Int64,
  failed_requests      Int64,
  window_index         Nullable(Int64),
  window_current       Nullable(Int64),
  window_previous      Nullable(Int64),
  total                Nullable(Float64),
  effective_limit      Nullable(Float64),
  expires_at           Nullable(DateTime64(3, 'UTC')),
  release_source       LowCardinality(String),
  operator_client_id   LowCardinality(String),
  operator_auth_method LowCardinality(String),
  keys_removed         Nullable(Int64),
  INDEX idx_bfl_bucket bucket_id TYPE bloom_filter GRANULARITY 4
) ENGINE = ReplacingMergeTree
PARTITION BY toYYYYMM(ts)
ORDER BY (deployment, network, ts, kind, event_id)
TTL toDateTime(ts) + INTERVAL 400 DAY DELETE
SETTINGS index_granularity = 8192;

-- Raw counted, tolerated, and hit events; short retention in daily parts that expire whole.
CREATE TABLE IF NOT EXISTS nauthilus.bruteforce_attempts (
  ts                 DateTime64(3, 'UTC'),
  event_id           String,
  event_version      UInt16,
  kind               LowCardinality(String),
  deployment         LowCardinality(String),
  instance           LowCardinality(String),
  request_id         String,
  client_ip          String,
  network            String,
  ip_family          UInt8,
  cidr               UInt8,
  rule               LowCardinality(String),
  rule_fingerprint   LowCardinality(String),
  bucket_id          String,
  bucket_protocol    LowCardinality(String),
  bucket_oidc_client LowCardinality(String),
  period_seconds     Int64,
  ban_time_seconds   Int64,
  failed_requests    Int64,
  window_index       Nullable(Int64),
  weight             Nullable(Float64),
  window_current     Nullable(Int64),
  window_previous    Nullable(Int64),
  total              Nullable(Float64),
  effective_limit    Nullable(Float64),
  crossed            Nullable(Bool),
  count_source       LowCardinality(String),
  ban_active         Nullable(Bool),
  claimed_username   String, -- a claim, never an identity; users can type secrets into this field
  account            String,
  account_known      Nullable(Bool),
  protocol           LowCardinality(String),
  oidc_client_id     LowCardinality(String),
  hit_source         LowCardinality(String),
  INDEX idx_bfa_client_ip client_ip TYPE bloom_filter GRANULARITY 4,
  INDEX idx_bfa_request request_id TYPE bloom_filter GRANULARITY 4
) ENGINE = ReplacingMergeTree
PARTITION BY toDate(ts)
ORDER BY (deployment, network, bucket_id, ts, event_id)
TTL toDate(ts) + INTERVAL 14 DAY DELETE
SETTINGS index_granularity = 8192, ttl_only_drop_parts = 1;

-- Hourly aggregate of attempts that outlives the raw rows; distinct name counts are HLL states, never raw names.
CREATE TABLE IF NOT EXISTS nauthilus.bruteforce_attempt_summary (
  hour              DateTime('UTC'),
  deployment        LowCardinality(String),
  network           String,
  bucket_id         String,
  kind              LowCardinality(String),
  rule              LowCardinality(String),
  window_index      Int64,
  events            SimpleAggregateFunction(sum, UInt64),
  ban_active_events SimpleAggregateFunction(sum, UInt64),
  min_current       SimpleAggregateFunction(min, Nullable(Int64)),
  max_current       SimpleAggregateFunction(max, Nullable(Int64)),
  first_ts          SimpleAggregateFunction(min, DateTime64(3, 'UTC')),
  last_ts           SimpleAggregateFunction(max, DateTime64(3, 'UTC')),
  claimed_names     AggregateFunction(uniq, String),
  accounts          AggregateFunction(uniq, String)
) ENGINE = AggregatingMergeTree
PARTITION BY toYYYYMM(hour)
ORDER BY (deployment, network, bucket_id, kind, window_index, hour, rule)
TTL hour + INTERVAL 400 DAY DELETE
SETTINGS index_granularity = 8192;

CREATE MATERIALIZED VIEW IF NOT EXISTS nauthilus.bruteforce_attempt_summary_mv
TO nauthilus.bruteforce_attempt_summary AS
SELECT
  toStartOfHour(ts) AS hour,
  deployment,
  network,
  bucket_id,
  kind,
  rule,
  ifNull(window_index, -1) AS window_index,
  count() AS events,
  countIf(ban_active = true) AS ban_active_events,
  min(window_current) AS min_current,
  max(window_current) AS max_current,
  min(ts) AS first_ts,
  max(ts) AS last_ts,
  uniqStateIf(claimed_username, claimed_username != '') AS claimed_names,
  uniqStateIf(account, account != '') AS accounts
FROM nauthilus.bruteforce_attempts
GROUP BY hour, deployment, network, bucket_id, kind, rule, window_index;

/*
Legacy upgrade guide (run online, one by one). Most statements are safe to repeat.
The legacy features column is no longer part of the supported ClickHouse contract; use decision_sources.

ALTER TABLE nauthilus.logins MODIFY COLUMN service            LowCardinality(String) CODEC(ZSTD(3));
ALTER TABLE nauthilus.logins ADD COLUMN IF NOT EXISTS deployment LowCardinality(String) DEFAULT '' CODEC(ZSTD(3)) AFTER service;
ALTER TABLE nauthilus.logins ADD COLUMN IF NOT EXISTS instance LowCardinality(String) DEFAULT '' CODEC(ZSTD(3)) AFTER deployment;
ALTER TABLE nauthilus.logins ADD COLUMN IF NOT EXISTS decision_sources LowCardinality(String) CODEC(ZSTD(3)) AFTER instance;
ALTER TABLE nauthilus.logins MODIFY COLUMN decision_sources   LowCardinality(String) CODEC(ZSTD(3));
ALTER TABLE nauthilus.logins ADD COLUMN IF NOT EXISTS rbl_lists Array(LowCardinality(String)) AFTER decision_sources;
ALTER TABLE nauthilus.logins MODIFY COLUMN client_net         LowCardinality(String);
ALTER TABLE nauthilus.logins MODIFY COLUMN client_id          LowCardinality(String);
ALTER TABLE nauthilus.logins MODIFY COLUMN hostname           LowCardinality(String) CODEC(ZSTD(3));
ALTER TABLE nauthilus.logins MODIFY COLUMN proto              LowCardinality(String);
ALTER TABLE nauthilus.logins MODIFY COLUMN user_agent         LowCardinality(String) CODEC(ZSTD(5));
ALTER TABLE nauthilus.logins MODIFY COLUMN local_ip           LowCardinality(String);
ALTER TABLE nauthilus.logins MODIFY COLUMN display_name       LowCardinality(String);
ALTER TABLE nauthilus.logins MODIFY COLUMN account            LowCardinality(String);
ALTER TABLE nauthilus.logins MODIFY COLUMN username           LowCardinality(String);
ALTER TABLE nauthilus.logins MODIFY COLUMN pwnd_info          LowCardinality(String);
ALTER TABLE nauthilus.logins MODIFY COLUMN brute_force_bucket LowCardinality(String);
ALTER TABLE nauthilus.logins MODIFY COLUMN oidc_cid           LowCardinality(String);
ALTER TABLE nauthilus.logins MODIFY COLUMN saml_entity_id     LowCardinality(String);
ALTER TABLE nauthilus.logins MODIFY COLUMN grant_type         LowCardinality(String);
ALTER TABLE nauthilus.logins MODIFY COLUMN mfa_method         LowCardinality(String);
ALTER TABLE nauthilus.logins MODIFY COLUMN geoip_guid         LowCardinality(String);
ALTER TABLE nauthilus.logins MODIFY COLUMN geoip_country      LowCardinality(String);
ALTER TABLE nauthilus.logins MODIFY COLUMN geoip_iso_codes    LowCardinality(String);
ALTER TABLE nauthilus.logins MODIFY COLUMN geoip_status       LowCardinality(String);
ALTER TABLE nauthilus.logins MODIFY COLUMN geoip_source       LowCardinality(String);
ALTER TABLE nauthilus.logins MODIFY COLUMN geoip_country_name LowCardinality(String);
ALTER TABLE nauthilus.logins MODIFY COLUMN geoip_city_name    LowCardinality(String);
ALTER TABLE nauthilus.logins MODIFY COLUMN geoip_asn_org      LowCardinality(String);
ALTER TABLE nauthilus.logins MODIFY COLUMN geoip_asn_prefix   LowCardinality(String);
ALTER TABLE nauthilus.logins MODIFY COLUMN geoip_asn_registry LowCardinality(String);
ALTER TABLE nauthilus.logins MODIFY COLUMN geoip_asn_country  LowCardinality(String);
ALTER TABLE nauthilus.logins MODIFY COLUMN geoip_asn_allocated LowCardinality(String);
ALTER TABLE nauthilus.logins MODIFY COLUMN geoip_asn_status   LowCardinality(String);
ALTER TABLE nauthilus.logins MODIFY COLUMN reputation_source  LowCardinality(String);
ALTER TABLE nauthilus.logins MODIFY COLUMN reputation_decision LowCardinality(String);
ALTER TABLE nauthilus.logins MODIFY COLUMN prot_reason        LowCardinality(String);
ALTER TABLE nauthilus.logins MODIFY COLUMN dyn_response       LowCardinality(String);
ALTER TABLE nauthilus.logins MODIFY COLUMN xssl_protocol      LowCardinality(String);
ALTER TABLE nauthilus.logins MODIFY COLUMN xssl_cipher        LowCardinality(String);
ALTER TABLE nauthilus.logins MODIFY COLUMN ssl_fingerprint    LowCardinality(String);

ALTER TABLE nauthilus.logins ADD COLUMN IF NOT EXISTS method      LowCardinality(String) AFTER proto;
ALTER TABLE nauthilus.logins ADD COLUMN IF NOT EXISTS latency     UInt64                 AFTER ssl_fingerprint;
ALTER TABLE nauthilus.logins ADD COLUMN IF NOT EXISTS http_status UInt16                 AFTER latency;
ALTER TABLE nauthilus.logins ADD COLUMN IF NOT EXISTS status_msg  LowCardinality(String) AFTER http_status;
ALTER TABLE nauthilus.logins ADD COLUMN IF NOT EXISTS saml_entity_id LowCardinality(String) AFTER oidc_cid;
ALTER TABLE nauthilus.logins ADD COLUMN IF NOT EXISTS grant_type     LowCardinality(String) AFTER saml_entity_id;
ALTER TABLE nauthilus.logins ADD COLUMN IF NOT EXISTS mfa_method     LowCardinality(String) AFTER grant_type;

ALTER TABLE nauthilus.logins ADD COLUMN IF NOT EXISTS geoip_source LowCardinality(String) AFTER geoip_status;
ALTER TABLE nauthilus.logins ADD COLUMN IF NOT EXISTS geoip_matched Nullable(Bool) AFTER geoip_source;
ALTER TABLE nauthilus.logins ADD COLUMN IF NOT EXISTS geoip_country_name LowCardinality(String) AFTER geoip_matched;
ALTER TABLE nauthilus.logins ADD COLUMN IF NOT EXISTS geoip_city_name LowCardinality(String) AFTER geoip_country_name;
ALTER TABLE nauthilus.logins ADD COLUMN IF NOT EXISTS geoip_asn Nullable(UInt64) AFTER geoip_city_name;
ALTER TABLE nauthilus.logins ADD COLUMN IF NOT EXISTS geoip_asn_org LowCardinality(String) AFTER geoip_asn;
ALTER TABLE nauthilus.logins ADD COLUMN IF NOT EXISTS geoip_asn_prefix LowCardinality(String) AFTER geoip_asn_org;
ALTER TABLE nauthilus.logins ADD COLUMN IF NOT EXISTS geoip_asn_registry LowCardinality(String) AFTER geoip_asn_prefix;
ALTER TABLE nauthilus.logins ADD COLUMN IF NOT EXISTS geoip_asn_country LowCardinality(String) AFTER geoip_asn_registry;
ALTER TABLE nauthilus.logins ADD COLUMN IF NOT EXISTS geoip_asn_allocated LowCardinality(String) AFTER geoip_asn_country;
ALTER TABLE nauthilus.logins ADD COLUMN IF NOT EXISTS geoip_asn_status LowCardinality(String) AFTER geoip_asn_allocated;
ALTER TABLE nauthilus.logins ADD COLUMN IF NOT EXISTS geoip_privacy_lookup_state LowCardinality(String) AFTER geoip_asn_status;
ALTER TABLE nauthilus.logins ADD COLUMN IF NOT EXISTS geoip_privacy_detected Nullable(Bool) AFTER geoip_privacy_lookup_state;
ALTER TABLE nauthilus.logins ADD COLUMN IF NOT EXISTS geoip_privacy_classes Array(String) AFTER geoip_privacy_detected;
ALTER TABLE nauthilus.logins ADD COLUMN IF NOT EXISTS geoip_privacy_primary_class LowCardinality(String) AFTER geoip_privacy_classes;
ALTER TABLE nauthilus.logins ADD COLUMN IF NOT EXISTS geoip_privacy_confidence Nullable(Float64) AFTER geoip_privacy_primary_class;
ALTER TABLE nauthilus.logins ADD COLUMN IF NOT EXISTS geoip_privacy_source_authorities Array(String) AFTER geoip_privacy_confidence;
ALTER TABLE nauthilus.logins ADD COLUMN IF NOT EXISTS geoip_privacy_data_stale Nullable(Bool) AFTER geoip_privacy_source_authorities;
ALTER TABLE nauthilus.logins ADD COLUMN IF NOT EXISTS geoip_privacy_data_age_seconds Nullable(UInt64) AFTER geoip_privacy_data_stale;
ALTER TABLE nauthilus.logins ADD COLUMN IF NOT EXISTS geoip_is_tor_exit_node Nullable(Bool) AFTER geoip_privacy_data_age_seconds;
ALTER TABLE nauthilus.logins ADD COLUMN IF NOT EXISTS geoip_is_known_vpn_exit Nullable(Bool) AFTER geoip_is_tor_exit_node;
ALTER TABLE nauthilus.logins ADD COLUMN IF NOT EXISTS geoip_is_community_vpn_exit Nullable(Bool) AFTER geoip_is_known_vpn_exit;
ALTER TABLE nauthilus.logins ADD COLUMN IF NOT EXISTS geoip_is_public_proxy Nullable(Bool) AFTER geoip_is_community_vpn_exit;
ALTER TABLE nauthilus.logins ADD COLUMN IF NOT EXISTS geoip_is_privacy_relay Nullable(Bool) AFTER geoip_is_public_proxy;
ALTER TABLE nauthilus.logins ADD COLUMN IF NOT EXISTS geoip_is_hosting_network Nullable(Bool) AFTER geoip_is_privacy_relay;
ALTER TABLE nauthilus.logins ADD COLUMN IF NOT EXISTS geoip_is_shared_egress Nullable(Bool) AFTER geoip_is_hosting_network;
ALTER TABLE nauthilus.logins ADD COLUMN IF NOT EXISTS reputation_score Nullable(Float64) AFTER geoip_is_shared_egress;
ALTER TABLE nauthilus.logins ADD COLUMN IF NOT EXISTS reputation_positive_score Nullable(Float64) AFTER reputation_score;
ALTER TABLE nauthilus.logins ADD COLUMN IF NOT EXISTS reputation_negative_score Nullable(Float64) AFTER reputation_positive_score;
ALTER TABLE nauthilus.logins ADD COLUMN IF NOT EXISTS reputation_ip_score Nullable(Float64) AFTER reputation_negative_score;
ALTER TABLE nauthilus.logins ADD COLUMN IF NOT EXISTS reputation_asn_score Nullable(Float64) AFTER reputation_ip_score;
ALTER TABLE nauthilus.logins ADD COLUMN IF NOT EXISTS reputation_country_score Nullable(Float64) AFTER reputation_asn_score;
ALTER TABLE nauthilus.logins ADD COLUMN IF NOT EXISTS reputation_asn_country_score Nullable(Float64) AFTER reputation_country_score;
ALTER TABLE nauthilus.logins ADD COLUMN IF NOT EXISTS reputation_samples Nullable(UInt64) AFTER reputation_asn_country_score;
ALTER TABLE nauthilus.logins ADD COLUMN IF NOT EXISTS reputation_source LowCardinality(String) AFTER reputation_samples;
ALTER TABLE nauthilus.logins ADD COLUMN IF NOT EXISTS reputation_decision LowCardinality(String) AFTER reputation_source;

ALTER TABLE nauthilus.logins ADD COLUMN IF NOT EXISTS rwp Nullable(Bool) AFTER repeating;

-- Diagnostic data contract columns and the auth_events table: apply migrations/diagnostic-contract.sql.
-- Brute-force evidence tables and the summary view: apply migrations/bruteforce-evidence.sql.

-- Notes:
-- - These ALTERs trigger background mutation and re-encoding of affected parts.
-- - Keep session, client_ip, client_port, local_port, password_hash as-is due to likely high cardinality or specific semantics.
-- - You can adjust ZSTD level to taste; 3–5 is a practical range for UA/hostname.
*/
