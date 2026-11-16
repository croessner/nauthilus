-- Nauthilus ClickHouse diagnostic data contract (contract_version 1, auth event version 1).
-- Contract: contrib/plugins/clickhouse/DIAGNOSTIC_CONTRACT.md.
-- Apply before rolling out a writer of this contract. Every statement is additive and safe to repeat.
-- ClickHouse accepts JSONEachRow fields it does not know by default (input_format_skip_unknown_fields = 1), so a new
-- writer against an unmigrated table silently loses the new fields. Verify with the system.columns query at the end.
-- Existing rows keep contract_version = 0 and empty outcome columns; they are never rewritten or reinterpreted.
-- Keep these columns and the auth_events table on application rollback; do not drop collected data.

-- Writer separation columns that the native plugin has always emitted.
ALTER TABLE nauthilus.logins ADD COLUMN IF NOT EXISTS deployment LowCardinality(String) DEFAULT '' CODEC(ZSTD(3)) AFTER service;
ALTER TABLE nauthilus.logins ADD COLUMN IF NOT EXISTS instance LowCardinality(String) DEFAULT '' CODEC(ZSTD(3)) AFTER deployment;

-- Versioned row identity and the host-sealed terminal outcome.
ALTER TABLE nauthilus.logins ADD COLUMN IF NOT EXISTS contract_version UInt16 DEFAULT 0;
ALTER TABLE nauthilus.logins ADD COLUMN IF NOT EXISTS event_id String DEFAULT '';
ALTER TABLE nauthilus.logins ADD COLUMN IF NOT EXISTS operation LowCardinality(String) DEFAULT '';
ALTER TABLE nauthilus.logins ADD COLUMN IF NOT EXISTS outcome LowCardinality(String) DEFAULT '';
ALTER TABLE nauthilus.logins ADD COLUMN IF NOT EXISTS outcome_stage LowCardinality(String) DEFAULT '';
ALTER TABLE nauthilus.logins ADD COLUMN IF NOT EXISTS outcome_marker LowCardinality(String) DEFAULT '';
ALTER TABLE nauthilus.logins ADD COLUMN IF NOT EXISTS response_marker LowCardinality(String) DEFAULT '';
ALTER TABLE nauthilus.logins ADD COLUMN IF NOT EXISTS policy_rule LowCardinality(String) DEFAULT '';
ALTER TABLE nauthilus.logins ADD COLUMN IF NOT EXISTS tempfail_reason LowCardinality(String) DEFAULT '';
ALTER TABLE nauthilus.logins ADD COLUMN IF NOT EXISTS tempfail_checkpoint LowCardinality(String) DEFAULT '';
ALTER TABLE nauthilus.logins ADD COLUMN IF NOT EXISTS policy_status LowCardinality(String) DEFAULT '';
ALTER TABLE nauthilus.logins ADD COLUMN IF NOT EXISTS fsm_state LowCardinality(String) DEFAULT '';
ALTER TABLE nauthilus.logins ADD COLUMN IF NOT EXISTS transport LowCardinality(String) DEFAULT '';
ALTER TABLE nauthilus.logins ADD COLUMN IF NOT EXISTS transport_status Nullable(UInt16);
ALTER TABLE nauthilus.logins ADD COLUMN IF NOT EXISTS flow_ref String DEFAULT '';
ALTER TABLE nauthilus.logins ADD COLUMN IF NOT EXISTS brute_force_tolerated Nullable(Bool);
ALTER TABLE nauthilus.logins ADD COLUMN IF NOT EXISTS reputation_assessments Array(Tuple(
  fact LowCardinality(String), role LowCardinality(String), kind LowCardinality(String),
  state LowCardinality(String), profile LowCardinality(String), band LowCardinality(String),
  override LowCardinality(String), risk_score Nullable(Float64), trust_score Nullable(Float64),
  confidence Nullable(Float64), samples Nullable(Float64), source_diversity Nullable(Int64),
  age_seconds Nullable(Int64)));
ALTER TABLE nauthilus.logins ADD COLUMN IF NOT EXISTS reputation_truncated Bool DEFAULT false;
-- New rows only; legacy rows carry an empty flow_ref, so no MATERIALIZE INDEX mutation is needed.
ALTER TABLE nauthilus.logins ADD INDEX IF NOT EXISTS idx_flow_ref flow_ref TYPE bloom_filter GRANULARITY 64;

-- Purpose-bound step events; never a copy of login rows.
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

-- Verification (read-only):
-- SELECT name, type FROM system.columns WHERE database = 'nauthilus' AND table = 'logins'
--   AND name IN ('deployment', 'instance', 'contract_version', 'event_id', 'operation', 'outcome', 'outcome_stage',
--   'outcome_marker', 'response_marker', 'policy_rule', 'tempfail_reason', 'tempfail_checkpoint', 'policy_status',
--   'fsm_state', 'transport', 'transport_status', 'flow_ref', 'brute_force_tolerated', 'reputation_assessments',
--   'reputation_truncated') ORDER BY name;
-- SELECT name, engine FROM system.tables WHERE database = 'nauthilus' AND name = 'auth_events';
