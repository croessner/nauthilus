-- Copyright (C) 2024 Christian Rößner
--
-- This program is free software: you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation, either version 3 of the License, or
-- (at your option) any later version.
--
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
-- GNU General Public License for more details.
--
-- You should have received a copy of the GNU General Public License
-- along with this program. If not, see <https://www.gnu.org/licenses/>.

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
local nauthilus_keys = require("nauthilus_keys")

local prom = require("nauthilus_prometheus")
local nauthilus_redis = require("nauthilus_redis")
local time = require("time")

local PER_USER_ENABLED = nauthilus_util.toboolean(nauthilus_util.getenv("SECURITY_METRICS_PER_USER_ENABLED", "false"))
local SAMPLE_RATE = tonumber(nauthilus_util.getenv("SECURITY_METRICS_SAMPLE_RATE", "1")) or 0
local CUSTOM_REDIS_POOL = nauthilus_util.getenv("CUSTOM_REDIS_POOL_NAME", "default")

-- Deterministic string hash (djb2) to support stable sampling by username
-- Pure Lua implementation using modulo to keep values in unsigned 32-bit range
local function djb2_hash(s)
    local hash = 5381
    for i = 1, #s do
        local c = string.byte(s, i)
        -- djb2: hash = (hash * 33 + c) mod 2^32
        hash = (hash * 33 + c) % 4294967296
    end
    if hash < 0 then
        -- normalize to unsigned 32-bit range for deterministic sampling
        hash = hash + 4294967296
    end
    return hash
end

local function protocol_segment(request)
    local protocol = request.protocol
    if protocol == nil or protocol == "" then
        return "unknown"
    end
    return protocol
end

-- Decide whether to emit per-user metrics for this username
-- Rules:
--  - Only when SECURITY_METRICS_PER_USER_ENABLED=true
--  - Always emit if account is currently in protection set
--  - Otherwise, emit if username hashes into the sample bucket defined by SECURITY_METRICS_SAMPLE_RATE (0..1)
local function should_emit_per_user(client, username, request)
    if not username or username == "" then
        return false
    end

    local protocol = protocol_segment(request)

    if not PER_USER_ENABLED then
        return false
    end

    -- Always include protected accounts (check hash flag set by account_protection_mode)
    local nauthilus_keys = require("nauthilus_keys")
    local prot_hash_key = nauthilus_util.get_redis_key(request, "acct:" .. nauthilus_keys.account_tag(username) .. username .. ":proto:" .. protocol .. ":protection")
    local prot_active = nauthilus_redis.redis_hget(client, prot_hash_key, "active")
    if prot_active == "true" then
        return true
    end

    -- Deterministic sampling
    if SAMPLE_RATE <= 0 then
        return false
    end
    if SAMPLE_RATE >= 1 then
        return true
    end

    local h = djb2_hash(username)
    -- map to [0, 1)
    local frac = (h % 100000) / 100000.0
    return frac < SAMPLE_RATE
end

function nauthilus_call_feature(request)
    if request.no_auth then
        return nauthilus_builtin.FEATURE_TRIGGER_NO, nauthilus_builtin.FEATURES_ABORT_NO, nauthilus_builtin.FEATURE_RESULT_YES
    end

    local username = request.username or request.account or ""
    local now = time.unix()
    local protocol = protocol_segment(request)

    -- Get Redis connection
    local client = "default"
    if CUSTOM_REDIS_POOL ~= "default" then
        local err
        client, err = nauthilus_redis.get_redis_connection(CUSTOM_REDIS_POOL)
        nauthilus_util.if_error_raise(err)
    end

    -- Per-account gauges (guarded to avoid high cardinality)
    if username ~= "" and should_emit_per_user(client, username, request) then
        local tag = nauthilus_keys.account_tag(username)
        -- Batch reads: PFCOUNT(24h,7d) + fallback ZCOUNTs + failure ZCOUNTs (1h,24h,7d)
        local cmds = {
            { "pfcount", nauthilus_util.get_redis_key(request, "hll:acct:" .. tag .. username .. ":proto:" .. protocol .. ":ips:86400") },
            { "pfcount", nauthilus_util.get_redis_key(request, "hll:acct:" .. tag .. username .. ":proto:" .. protocol .. ":ips:604800") },
            { "zcount", nauthilus_util.get_redis_key(request, "multilayer:account:" .. tag .. username .. ":proto:" .. protocol .. ":ips:86400"), tostring(now - 86400), tostring(now) },
            { "zcount", nauthilus_util.get_redis_key(request, "multilayer:account:" .. tag .. username .. ":proto:" .. protocol .. ":ips:604800"), tostring(now - 604800), tostring(now) },
        }
        local zkey = nauthilus_util.get_redis_key(request, "z:acct:" .. tag .. username .. ":proto:" .. protocol .. ":fails")
        table.insert(cmds, {"zcount", zkey, tostring(now - 3600), tostring(now)})   -- 5
        table.insert(cmds, {"zcount", zkey, tostring(now - 86400), tostring(now)})  -- 6
        table.insert(cmds, {"zcount", zkey, tostring(now - 604800), tostring(now)}) -- 7

        local res, rerr = nauthilus_redis.redis_pipeline(client, "read", cmds)
        nauthilus_util.if_error_raise(rerr)

        local uniq24_pf = tonumber(res[1] and res[1].value or 0) or 0
        local uniq7d_pf = tonumber(res[2] and res[2].value or 0) or 0
        local uniq24_fallback = tonumber(res[3] and res[3].value or 0) or 0
        local uniq7d_fallback = tonumber(res[4] and res[4].value or 0) or 0

        local uniq24 = (uniq24_pf > 0) and uniq24_pf or uniq24_fallback
        local uniq7d = (uniq7d_pf > 0) and uniq7d_pf or uniq7d_fallback

        prom.set_gauge("security_unique_ips_per_user", uniq24, { username = username, window = "24h" })
        prom.set_gauge("security_unique_ips_per_user", uniq7d, { username = username, window = "7d" })

        local f1h = tonumber(res[5] and res[5].value or 0) or 0
        local f24 = tonumber(res[6] and res[6].value or 0) or 0
        local f7d = tonumber(res[7] and res[7].value or 0) or 0

        -- Fallback to multilayer failures if zero
        if f1h == 0 then
            local r2, e2 = nauthilus_redis.redis_pipeline(client, "read", {
                { "zcount", nauthilus_util.get_redis_key(request, "multilayer:account:" .. tag .. username .. ":proto:" .. protocol .. ":fails:3600"), tostring(now - 3600), tostring(now) }
            })
            nauthilus_util.if_error_raise(e2)
            f1h = tonumber(r2[1] and r2[1].value or 0) or 0
        end
        if f24 == 0 then
            local r2, e2 = nauthilus_redis.redis_pipeline(client, "read", {
                { "zcount", nauthilus_util.get_redis_key(request, "multilayer:account:" .. tag .. username .. ":proto:" .. protocol .. ":fails:86400"), tostring(now - 86400), tostring(now) }
            })
            nauthilus_util.if_error_raise(e2)
            f24 = tonumber(r2[1] and r2[1].value or 0) or 0
        end
        if f7d == 0 then
            local r2, e2 = nauthilus_redis.redis_pipeline(client, "read", {
                { "zcount", nauthilus_util.get_redis_key(request, "multilayer:account:" .. tag .. username .. ":proto:" .. protocol .. ":fails:604800"), tostring(now - 604800), tostring(now) }
            })
            nauthilus_util.if_error_raise(e2)
            f7d = tonumber(r2[1] and r2[1].value or 0) or 0
        end

        prom.set_gauge("security_account_fail_budget_used", f1h, { username = username, window = "1h" })
        prom.set_gauge("security_account_fail_budget_used", f24, { username = username, window = "24h" })
        prom.set_gauge("security_account_fail_budget_used", f7d, { username = username, window = "7d" })

        if (uniq7d >= 30) or (f7d >= 15) then
            prom.increment_counter("security_slow_attack_suspicions_total", { })
        end
    end

    -- Global ips_per_user over 24h and 7d (requires global_pattern_monitoring.lua to collect these windows)
    local cmds = {
        { "zcount", nauthilus_util.get_redis_key(request, "multilayer:global:auth_attempts:86400"), tostring(now - 86400), tostring(now) },
        { "zcount", nauthilus_util.get_redis_key(request, "multilayer:global:unique_ips:86400"), tostring(now - 86400), tostring(now) },
        { "zcount", nauthilus_util.get_redis_key(request, "multilayer:global:unique_users:86400"), tostring(now - 86400), tostring(now) },
        { "zcount", nauthilus_util.get_redis_key(request, "multilayer:global:auth_attempts:604800"), tostring(now - 604800), tostring(now) },
        { "zcount", nauthilus_util.get_redis_key(request, "multilayer:global:unique_ips:604800"), tostring(now - 604800), tostring(now) },
        { "zcount", nauthilus_util.get_redis_key(request, "multilayer:global:unique_users:604800"), tostring(now - 604800), tostring(now) },
    }
    local gres, gerr = nauthilus_redis.redis_pipeline(client, "read", cmds)
    nauthilus_util.if_error_raise(gerr)

    local a24 = tonumber(gres[1] and gres[1].value or 0) or 0
    local uip24 = tonumber(gres[2] and gres[2].value or 0) or 0
    local uusr24 = tonumber(gres[3] and gres[3].value or 0) or 0
    local a7d = tonumber(gres[4] and gres[4].value or 0) or 0
    local uip7d = tonumber(gres[5] and gres[5].value or 0) or 0
    local uusr7d = tonumber(gres[6] and gres[6].value or 0) or 0

    local g24 = 0.0
    local g7d = 0.0
    if uusr24 > 0 then g24 = uip24 / uusr24 end
    if uusr7d > 0 then g7d = uip7d / uusr7d end

    prom.set_gauge("security_global_ips_per_user", g24, { window = "24h" })
    prom.set_gauge("security_global_ips_per_user", g7d, { window = "7d" })

    -- Accounts in protection mode (size of Redis set maintained by account_protection_mode.lua)
    local prot_set = nauthilus_util.get_redis_key(request, "acct:protection_active:proto:" .. protocol)
    local prot_count = tonumber(nauthilus_redis.redis_scard(client, prot_set) or 0) or 0
    prom.set_gauge("security_accounts_in_protection_mode_total", prot_count, { })

    return nauthilus_builtin.FEATURE_TRIGGER_NO, nauthilus_builtin.FEATURES_ABORT_NO, nauthilus_builtin.FEATURE_RESULT_OK
end
