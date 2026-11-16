-- Nauthilus brute-force evidence tables (brute-force event_version 1).
-- Contract: contrib/plugins/clickhouse/DIAGNOSTIC_CONTRACT.md section 13.
-- Apply before configuring bruteforce_lifecycle_insert_url / bruteforce_attempts_insert_url. Every statement is
-- additive and safe to repeat. No existing table is changed; no data is rewritten or deleted.

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

-- Verification (read-only):
-- SELECT name, engine FROM system.tables WHERE database = 'nauthilus' AND name LIKE 'bruteforce_%' ORDER BY name;
