-- Dedicated read-only ClickHouse account for the Nauthilus support history service
-- (storage.history.clickhouse, budget_mode: query_settings). Access-control provisioning only; no schema change.
--
-- * readonly = 2 CONST: the account can never write, and the service may lower (never raise) the budgets per query.
-- * Every budget carries a MAX constraint; overflow modes are CONST 'throw', so a hit budget is an error and never
--   silently truncated rows.
-- * cancel_http_readonly_queries_on_client_close stops a query when the service gives up on it.
-- * The values must be at least the configured storage.history.clickhouse budgets (the service sends its own,
--   possibly lower, values with each query).
-- * Grant only the five diagnostic tables. Grafana or other accounts are not a substitute: they must not hold the
--   brute-force tables, which carry claimed login names (DIAGNOSTIC_CONTRACT.md §13.3).
--
-- For budget_mode: profile, use readonly = 1 CONST instead; the service then sends no settings and verifies the
-- effective values of this profile before every cached period of reads.
--
-- Replace CHANGE_ME_PASSWORD (or use IDENTIFIED WITH an external authenticator) before applying.

CREATE SETTINGS PROFILE IF NOT EXISTS nauthilus_history_profile SETTINGS
  readonly = 2 CONST,
  max_execution_time = 8 MAX 8,
  max_rows_to_read = 5000000 MAX 5000000,
  max_bytes_to_read = 2147483648 MAX 2147483648,
  read_overflow_mode = 'throw' CONST,
  result_overflow_mode = 'throw' CONST,
  timeout_overflow_mode = 'throw' CONST,
  cancel_http_readonly_queries_on_client_close = 1;

CREATE USER IF NOT EXISTS nauthilus_history IDENTIFIED WITH sha256_password BY 'CHANGE_ME_PASSWORD'
  SETTINGS PROFILE 'nauthilus_history_profile';

GRANT SELECT ON nauthilus.logins TO nauthilus_history;
GRANT SELECT ON nauthilus.auth_events TO nauthilus_history;
GRANT SELECT ON nauthilus.bruteforce_lifecycle TO nauthilus_history;
GRANT SELECT ON nauthilus.bruteforce_attempts TO nauthilus_history;
GRANT SELECT ON nauthilus.bruteforce_attempt_summary TO nauthilus_history;
