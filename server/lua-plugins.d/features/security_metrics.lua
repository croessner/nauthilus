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

dynamic_loader("nauthilus_gll_bit")
local bit = require("bit")

-- Deterministic string hash (djb2) to support stable sampling by username
local function djb2_hash(s)
    local hash = 5381
    for i = 1, #s do
        local c = string.byte(s, i)
        -- djb2: hash = ((hash << 5) + hash + c) & 0xffffffff
        hash = bit.band((bit.lshift(hash, 5) + hash + c), 0xFFFFFFFF)
    end
    if hash < 0 then
        -- normalize to unsigned 32-bit range for deterministic sampling
        hash = hash + 4294967296
    end
    return hash
end

-- Decide whether to emit per-user metrics for this username
-- Rules:
--  - Only when SECURITY_METRICS_PER_USER_ENABLED=true
--  - Always emit if account is currently in protection set
--  - Otherwise, emit if username hashes into the sample bucket defined by SECURITY_METRICS_SAMPLE_RATE (0..1)
local function should_emit_per_user(client, username)
    if not username or username == "" then
        return false
    end

    local enabled = os.getenv("SECURITY_METRICS_PER_USER_ENABLED")
    if not enabled or enabled == "" or string.lower(enabled) == "false" or enabled == "0" then
        return false
    end

    -- Always include protected accounts (check hash flag set by account_protection_mode)
    local prot_hash_key = "ntc:acct:" .. username .. ":protection"
    local prot_active = r.redis_hget(client, prot_hash_key, "active")
    if prot_active == "true" then
        return true
    end

    -- Deterministic sampling
    local rate_env = os.getenv("SECURITY_METRICS_SAMPLE_RATE")
    local rate
    if rate_env == nil or rate_env == "" then
        -- If per-user metrics are enabled and sample rate is unset, default to 100% sampling
        rate = 1
    else
        rate = tonumber(rate_env) or 0
    end

    if rate <= 0 then
        return false
    end
    if rate >= 1 then
        return true
    end

    local h = djb2_hash(username)
    -- map to [0, 1)
    local frac = (h % 100000) / 100000.0
    return frac < rate
end

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

    -- Per-account gauges (guarded to avoid high cardinality)
    if username ~= "" and should_emit_per_user(client, username) then
        -- unique IPs per user over 24h and 7d (prefer HLL; fallback to multilayer ZSET if HLL unavailable)
        local uniq24 = tonumber(r.redis_pfcount(client, "ntc:hll:acct:" .. username .. ":ips:86400")) or 0
        local uniq7d = tonumber(r.redis_pfcount(client, "ntc:hll:acct:" .. username .. ":ips:604800")) or 0

        if uniq24 == 0 then
            uniq24 = tonumber(r.redis_zcount(client, "ntc:multilayer:account:" .. username .. ":ips:86400", now - 86400, now)) or 0
        end
        if uniq7d == 0 then
            uniq7d = tonumber(r.redis_zcount(client, "ntc:multilayer:account:" .. username .. ":ips:604800", now - 604800, now)) or 0
        end

        prom.set_gauge("security_unique_ips_per_user", uniq24, { username = username, window = "24h" })
        prom.set_gauge("security_unique_ips_per_user", uniq7d, { username = username, window = "7d" })

        -- failures in 1h/24h/7d windows (prefer account_longwindow ZSET; fallback to multilayer ZSET)
        local zkey = "ntc:z:acct:" .. username .. ":fails"
        local f1h = tonumber(r.redis_zcount(client, zkey, now - 3600, now)) or 0
        local f24 = tonumber(r.redis_zcount(client, zkey, now - 86400, now)) or 0
        local f7d = tonumber(r.redis_zcount(client, zkey, now - 604800, now)) or 0

        if f1h == 0 then
            f1h = tonumber(r.redis_zcount(client, "ntc:multilayer:account:" .. username .. ":fails:3600", now - 3600, now)) or 0
        end
        if f24 == 0 then
            f24 = tonumber(r.redis_zcount(client, "ntc:multilayer:account:" .. username .. ":fails:86400", now - 86400, now)) or 0
        end
        if f7d == 0 then
            f7d = tonumber(r.redis_zcount(client, "ntc:multilayer:account:" .. username .. ":fails:604800", now - 604800, now)) or 0
        end

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
