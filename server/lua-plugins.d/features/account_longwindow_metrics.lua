-- Copyright (C) 2025 Christian Rößner
--
-- GPLv3-or-later
--
-- Phase 1 implementation from docs/attacker_detection_ideas.md:
--  - Per-account unique IPs via HyperLogLog over 24h and 7d windows
--  - Per-account failure timestamps over up to 7d
--  - Optional privacy-preserving password-spray token counters (if provided)
-- This feature only collects metrics and never blocks; it is safe to enable in learning mode.

local N = "account_longwindow_metrics"

local nauthilus_util = require("nauthilus_util")

dynamic_loader("nauthilus_redis")
local nauthilus_redis = require("nauthilus_redis")

dynamic_loader("nauthilus_misc")
local nauthilus_misc = require("nauthilus_misc")

dynamic_loader("nauthilus_gll_time")
local time = require("time")

dynamic_loader("nauthilus_prometheus")
local nauthilus_prometheus = require("nauthilus_prometheus")

function nauthilus_call_feature(request)
    -- This feature should run regardless of success/failure, but respect no_auth
    if request.no_auth then
        return nauthilus_builtin.FEATURE_TRIGGER_NO, nauthilus_builtin.FEATURES_ABORT_NO, nauthilus_builtin.FEATURE_RESULT_YES
    end

    -- Derive context
    local username = request.username or request.account -- some protocols fill account
    local client_ip = request.client_ip
    local authenticated = (request.authenticated == true)
    local req_id = request.request_id or (tostring(os.time()) .. "_" .. tostring(math.random(1000000)))
    local now = os.time()

    -- Get Redis connection
    local client = "default"
    local pool_name = os.getenv("CUSTOM_REDIS_POOL_NAME")
    if pool_name ~= nil and pool_name ~= "" then
        local err
        client, err = nauthilus_redis.get_redis_connection(pool_name)
        nauthilus_util.if_error_raise(err)
    end

    -- Only collect per-account metrics if we have a username
    if username and username ~= "" then
        -- 1) Unique IPs per account using HLL for 24h and 7d
        if client_ip and client_ip ~= "" then
            local scoped = nauthilus_misc.scoped_ip("lua_generic", client_ip)
            if not scoped or scoped == "" then scoped = client_ip end
            local windows = { 86400, 604800 } -- 24h, 7d
            -- Batch HLL updates and TTLs via pipeline
            local pipe_cmds = {}
            for _, w in ipairs(windows) do
                local hll_key = "ntc:hll:acct:" .. username .. ":ips:" .. w
                table.insert(pipe_cmds, {"pfadd", hll_key, scoped})
                table.insert(pipe_cmds, {"expire", hll_key, w * 2})
            end
            if #pipe_cmds > 0 then
                local _, perr = nauthilus_redis.redis_pipeline(client, "write", pipe_cmds)
                nauthilus_util.if_error_raise(perr)
            end
        end

        -- 2) Per-account failures ZSET (keep max 7d)
        if not authenticated then
            local zkey = "ntc:z:acct:" .. username .. ":fails"
            -- Use request id to avoid duplicates as member
            local pipe_cmds = {
                {"zadd", zkey, now, req_id},
                {"zremrangebyscore", zkey, "0", tostring(now - 604800)},
                {"expire", zkey, 604800 * 2},
            }
            local _, perr = nauthilus_redis.redis_pipeline(client, "write", pipe_cmds)
            nauthilus_util.if_error_raise(perr)
        end
    end

    -- 3) Password spraying: privacy-preserving token counters (direct generation)
    -- Generate a short, stable password token locally from request.password, as in actions/clickhouse.lua
    -- No plaintext is persisted or logged. If no password is present, nothing is counted.
    local pw_token
    if request.password and request.password ~= "" then
        dynamic_loader("nauthilus_password")
        local nauthilus_password = require("nauthilus_password")

        local ok, token = pcall(nauthilus_password.generate_password_hash, request.password)
        if ok and token and token ~= "" then
            pw_token = token
        end
    end

    if pw_token and pw_token ~= "" then
        local windows = { 86400, 604800 } -- 24h, 7d
        -- Batch window updates for spray tokens
        local pipe_cmds = {}
        for _, w in ipairs(windows) do
            local zkey = "ntc:z:spray:pw:" .. w
            table.insert(pipe_cmds, {"zadd", zkey, now, pw_token})
            table.insert(pipe_cmds, {"zremrangebyscore", zkey, "0", tostring(now - w)})
            table.insert(pipe_cmds, {"expire", zkey, w * 2})

            local label = (w == 86400) and "24h" or "7d"
            nauthilus_prometheus.increment_counter("security_sprayed_password_tokens_total", { window = label })
        end
        if #pipe_cmds > 0 then
            local _, perr = nauthilus_redis.redis_pipeline(client, "write", pipe_cmds)
            nauthilus_util.if_error_raise(perr)
        end
    end

    -- Optional: store quick snapshot metrics for account to simplify Phase 2 lookups
    if username and username ~= "" then
        local uniq24 = 0
        local uniq7d = 0
        if client_ip and client_ip ~= "" then
            uniq24 = tonumber(nauthilus_redis.redis_pfcount(client, "ntc:hll:acct:" .. username .. ":ips:86400")) or 0
            uniq7d = tonumber(nauthilus_redis.redis_pfcount(client, "ntc:hll:acct:" .. username .. ":ips:604800")) or 0
        end
        local fails_24h = 0
        local fails_7d = 0
        local fail_key = "ntc:z:acct:" .. username .. ":fails"
        fails_24h = tonumber(nauthilus_redis.redis_zcount(client, fail_key, now - 86400, now)) or 0
        fails_7d = tonumber(nauthilus_redis.redis_zcount(client, fail_key, now - 604800, now)) or 0

        -- Save snapshot
        local _, err_script = nauthilus_redis.redis_run_script(
            client,
            "",
            "HSetMultiExpire",
            {"ntc:acct:" .. username .. ":longwindow"},
            {
                86400, -- keep 24h snapshot around a day
                "uniq_ips_24h", uniq24,
                "uniq_ips_7d", uniq7d,
                "fails_24h", fails_24h,
                "fails_7d", fails_7d,
                "last_updated", now
            }
        )
        nauthilus_util.if_error_raise(err_script)
    end

    -- Logging: keep it lightweight
    local logs = {
        caller = N .. ".lua",
        level = "info",
        message = "Phase1 metrics updated",
        username = username,
        client_ip = client_ip,
        authenticated = authenticated,
        has_pw_token = (pw_token ~= nil),
        ts = now,
    }
    nauthilus_util.print_result({ log_format = "json" }, logs)

    return nauthilus_builtin.FEATURE_TRIGGER_NO, nauthilus_builtin.FEATURES_ABORT_NO, nauthilus_builtin.FEATURE_RESULT_OK
end
