-- Copyright (C) 2025 Christian Rößner
--
-- GPLv3-or-later
--
-- security_* Prometheus metrics from docs/attacker_detection_ideas.md.
-- This plugin reads per-account and global data from Redis and updates
-- Prometheus metrics. It does not block or affect auth decisions.
--
-- Metrics updated:
--  - security_unique_ips_per_user{username,window}
--  - security_account_fail_budget_used{username,window}
--  - security_global_ips_per_user{window}
--  - security_accounts_in_protection_mode_total
--  - security_slow_attack_suspicions_total (heuristic; increments when protection mode is active)
--
-- Other metrics are incremented from their corresponding feature/action:
--  - security_sprayed_password_tokens_total{window} -> account_longwindow_metrics.lua
--  - security_stepup_challenges_issued_total -> account_protection_mode.lua
--  - security_pow_challenges_issued_total -> TBD when PoW is implemented

local N = "security_metrics"

local nauthilus_util = require("nauthilus_util")

dynamic_loader("nauthilus_prometheus")
local prom = require("nauthilus_prometheus")

dynamic_loader("nauthilus_redis")
local r = require("nauthilus_redis")

function nauthilus_call_feature(request)
    if request.no_auth then
        return nauthilus_builtin.FEATURE_TRIGGER_NO, nauthilus_builtin.FEATURES_ABORT_NO, nauthilus_builtin.FEATURE_RESULT_YES
    end

    local username = request.username or request.account or ""
    local now = os.time()

    -- Get Redis connection
    local client = "default"
    local pool_name = os.getenv("CUSTOM_REDIS_POOL_NAME")
    if pool_name ~= nil and pool_name ~= "" then
        local err
        client, err = r.get_redis_connection(pool_name)
        nauthilus_util.if_error_raise(err)
    end

    -- Per-account gauges (if username present)
    if username ~= "" then
        -- unique IPs per user over 24h and 7d (PFCOUNT)
        local uniq24 = tonumber(r.redis_pfcount(client, "ntc:hll:acct:" .. username .. ":ips:86400")) or 0
        local uniq7d = tonumber(r.redis_pfcount(client, "ntc:hll:acct:" .. username .. ":ips:604800")) or 0

        prom.set_gauge("security_unique_ips_per_user", uniq24, { username = username, window = "24h" })
        prom.set_gauge("security_unique_ips_per_user", uniq7d, { username = username, window = "7d" })

        -- failures in 1h/24h/7d windows (ZCOUNT)
        local zkey = "ntc:z:acct:" .. username .. ":fails"
        local f1h = tonumber(r.redis_zcount(client, zkey, now - 3600, now)) or 0
        local f24 = tonumber(r.redis_zcount(client, zkey, now - 86400, now)) or 0
        local f7d = tonumber(r.redis_zcount(client, zkey, now - 604800, now)) or 0

        prom.set_gauge("security_account_fail_budget_used", f1h, { username = username, window = "1h" })
        prom.set_gauge("security_account_fail_budget_used", f24, { username = username, window = "24h" })
        prom.set_gauge("security_account_fail_budget_used", f7d, { username = username, window = "7d" })

        -- Heuristic suspicion: if uniq7d is high or failures are high, increment a suspicion counter.
        if (uniq7d >= 30) or (f7d >= 15) then
            prom.increment_counter("security_slow_attack_suspicions_total", { })
        end
    end

    -- Global ips_per_user over 24h and 7d (requires global_pattern_monitoring.lua to collect these windows)
    local function get_metric(window)
        local attempts = tonumber(r.redis_zcount(client, "ntc:multilayer:global:auth_attempts:" .. window, now - window, now)) or 0
        local unique_ips = tonumber(r.redis_zcount(client, "ntc:multilayer:global:unique_ips:" .. window, now - window, now)) or 0
        local unique_users = tonumber(r.redis_zcount(client, "ntc:multilayer:global:unique_users:" .. window, now - window, now)) or 0
        local ips_per_user = 0.0
        if unique_users > 0 then ips_per_user = unique_ips / unique_users end
        return ips_per_user
    end

    local g24 = get_metric(86400)
    local g7d = get_metric(604800)

    prom.set_gauge("security_global_ips_per_user", g24, { window = "24h" })
    prom.set_gauge("security_global_ips_per_user", g7d, { window = "7d" })

    -- Accounts in protection mode (size of Redis set maintained by account_protection_mode.lua)
    local prot_set = "ntc:acct:protection_active"
    local prot_count = tonumber(r.redis_scard(client, prot_set) or 0) or 0
    prom.set_gauge("security_accounts_in_protection_mode_total", prot_count, { })

    return nauthilus_builtin.FEATURE_TRIGGER_NO, nauthilus_builtin.FEATURES_ABORT_NO, nauthilus_builtin.FEATURE_RESULT_OK
end
