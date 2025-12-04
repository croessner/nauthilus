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

local nauthilus_util = require("nauthilus_util")

local nauthilus_http_request = require("nauthilus_http_request")
local nauthilus_redis = require("nauthilus_redis")

local N = "distributed-brute-force-admin"

-- Ensure system start and warm-up settings exist; return settings table
local function ensure_startup_settings(redis_handle)
    local settings_key = "ntc:multilayer:global:settings"
    local settings = nauthilus_redis.redis_hgetall(redis_handle, settings_key) or {}

    -- system_started_at: unix timestamp
    if not settings["system_started_at"] or settings["system_started_at"] == "" then
        local now = os.time()
        -- Persist only if missing
        nauthilus_redis.redis_hset(redis_handle, settings_key, "system_started_at", tostring(now))
        settings["system_started_at"] = tostring(now)
    end

    -- warmup_window_seconds: from env or default 86400 (24h)
    local env_warmup = os.getenv("NAUTHILUS_WARMUP_WINDOW_SECONDS")
    local default_warmup = tostring(86400)
    local warmup_value = env_warmup and tostring(tonumber(env_warmup) or 0) or nil
    if not warmup_value or tonumber(warmup_value) == nil or tonumber(warmup_value) <= 0 then
        warmup_value = default_warmup
    end

    if not settings["warmup_window_seconds"] or settings["warmup_window_seconds"] == "" then
        nauthilus_redis.redis_hset(redis_handle, settings_key, "warmup_window_seconds", warmup_value)
        settings["warmup_window_seconds"] = warmup_value
    end

    return settings
end

-- Helper function to get metrics from Redis
local function get_metrics(redis_handle)
    local metrics = {}

    -- Make sure startup-related settings exist
    local settings = ensure_startup_settings(redis_handle)

    -- Keys
    local settings_key = "ntc:multilayer:global:settings"
    local current_metrics_key = "ntc:multilayer:global:current_metrics"
    local attacked_accounts_key = "ntc:multilayer:distributed_attack:accounts"
    local blocked_regions_key = "ntc:multilayer:global:blocked_regions"
    local rate_limited_ips_key = "ntc:multilayer:global:rate_limited_ips"
    local captcha_accounts_key = "ntc:multilayer:global:captcha_accounts"
    local first_seen_key = "ntc:multilayer:bootstrap:first_seen_ts"

    -- Batch reads via pipeline: threat_level, current metrics, attacked accounts, blocked/rate/captcha sets, first_seen
    local cmds = {
        {"hget", settings_key, "threat_level"},
        {"hmget", current_metrics_key, "attempts", "unique_ips", "unique_users", "ips_per_user"},
        {"zrange", attacked_accounts_key, 0, -1, "WITHSCORES"},
        {"smembers", blocked_regions_key},
        {"smembers", rate_limited_ips_key},
        {"smembers", captcha_accounts_key},
        {"get", first_seen_key},
    }
    local res, rerr = nauthilus_redis.redis_pipeline(redis_handle, "read", cmds)
    nauthilus_util.if_error_raise(rerr)

    -- Extract
    local threat_level_str = res[1] and res[1].value or "0.0"
    metrics.threat_level = tonumber(threat_level_str) or 0.0

    do
        local v = (res[2] and res[2].value) or {}
        metrics.attempts = tonumber(v[1] or 0) or 0
        metrics.unique_ips = tonumber(v[2] or 0) or 0
        metrics.unique_users = tonumber(v[3] or 0) or 0
        metrics.ips_per_user = tonumber(v[4] or 0) or 0
    end

    metrics.attacked_accounts = (res[3] and res[3].value) or {}
    metrics.blocked_regions = (res[4] and res[4].value) or {}
    metrics.rate_limited_ips = (res[5] and res[5].value) or {}
    metrics.captcha_accounts = (res[6] and res[6].value) or {}

    -- Compute warm-up diagnostics (aligned with dynamic_response.lua gating)
    local now = os.time()
    local warmup_seconds = tonumber(os.getenv("DYNAMIC_RESPONSE_WARMUP_SECONDS") or "3600")
    local warmup_min_users = tonumber(os.getenv("DYNAMIC_RESPONSE_WARMUP_MIN_USERS") or "1000")
    local warmup_min_attempts = tonumber(os.getenv("DYNAMIC_RESPONSE_WARMUP_MIN_ATTEMPTS") or "10000")

    local first_seen_val = res[7] and res[7].value or nil
    local first_seen_ts = tonumber(first_seen_val or "0") or 0
    if first_seen_ts == 0 then
        -- Initialize on first call to provide immediate feedback to UI; best-effort with TTL 30d
        nauthilus_redis.redis_set(redis_handle, first_seen_key, tostring(now), 30 * 24 * 3600)
        first_seen_ts = now
    end

    local elapsed = math.max(0, now - first_seen_ts)
    local seconds_progress = (warmup_seconds > 0) and math.min(1.0, elapsed / warmup_seconds) or 1.0
    local users_progress = (warmup_min_users > 0) and math.min(1.0, (metrics.unique_users or 0) / warmup_min_users) or 1.0
    local attempts_progress = (warmup_min_attempts > 0) and math.min(1.0, (metrics.attempts or 0) / warmup_min_attempts) or 1.0
    local overall_progress = math.min(seconds_progress, users_progress, attempts_progress)

    local warmed_up = (elapsed >= warmup_seconds) and ((metrics.unique_users or 0) >= warmup_min_users) and ((metrics.attempts or 0) >= warmup_min_attempts)

    -- Legacy/top-level fields used by UI consumers
    metrics.warmup_progress = overall_progress
    metrics.warmup_complete = warmed_up

    -- Detailed warm-up info for rich UIs
    metrics.warmup = {
        first_seen_ts = first_seen_ts,
        now_ts = now,
        elapsed_seconds = elapsed,
        requirements = {
            seconds = warmup_seconds,
            min_users = warmup_min_users,
            min_attempts = warmup_min_attempts
        },
        progress = {
            seconds = seconds_progress,
            users = users_progress,
            attempts = attempts_progress,
            overall = overall_progress
        },
        warmed_up = warmed_up
    }

    -- Keep startup settings for backward compatibility
    metrics.settings = settings or {}

    return metrics
end

-- Helper function to reset protection measures
local function reset_protection_measures(redis_handle)
    -- Reset global settings
    local _, err_script = nauthilus_redis.redis_run_script(
        redis_handle, 
        "", 
        "HSetMultiExpire", 
        {"ntc:multilayer:global:settings"}, 
        {
            3600, -- Expire after 1 hour
            "captcha_enabled", "false",
            "rate_limit_enabled", "false",
            "monitoring_mode", "false",
            "threat_level", "0.0"
        }
    )
    nauthilus_util.if_error_raise(err_script)

    -- Delete blocked regions, rate limited IPs, and captcha accounts using a single pipeline
    local pipeline_cmds = {
        {"del", "ntc:multilayer:global:blocked_regions"},
        {"del", "ntc:multilayer:global:rate_limited_ips"},
        {"del", "ntc:multilayer:global:captcha_accounts"},
    }
    local _, pipe_err = nauthilus_redis.redis_pipeline(redis_handle, "write", pipeline_cmds)
    nauthilus_util.if_error_raise(pipe_err)

    return true
end

-- Helper function to reset a specific account
local function reset_account(redis_handle, username)
    if not username or username == "" then
        return false, "Username is required"
    end

    -- Prepare keys and members
    local attacked_accounts_key = "ntc:multilayer:distributed_attack:accounts"
    local captcha_accounts_key = "ntc:multilayer:global:captcha_accounts"

    local window = 3600 -- 1 hour window
    local ip_key = "nauthilus:account:" .. username .. ":ips:" .. window
    local fail_key = "nauthilus:account:" .. username .. ":fails:" .. window

    -- Load all IPs seen for this account (read) to build the deletion pipeline
    local pw_hist_ips_key = "PW_HIST_IPS:" .. username
    local ips = nauthilus_redis.redis_smembers(redis_handle, pw_hist_ips_key) or {}

    -- Build a single write pipeline to delete all related keys and set entries
    local pipeline_cmds = {
        {"zrem", attacked_accounts_key, { username }},
        {"srem", captcha_accounts_key, username},
        {"del", ip_key},
        {"del", fail_key},
        {"srem", "AFFECTED_ACCOUNTS", username},
    }

    for _, ip in ipairs(ips) do
        table.insert(pipeline_cmds, {"del", "PW_HIST:" .. username .. ":" .. ip})
        table.insert(pipeline_cmds, {"del", "PW_HIST:" .. ip})
        table.insert(pipeline_cmds, {"del", "PW_HIST_META:" .. ip})
        table.insert(pipeline_cmds, {"del", "bf:TR:" .. ip})
        table.insert(pipeline_cmds, {"del", "bf:TR:" .. ip .. ":P"})
        table.insert(pipeline_cmds, {"del", "bf:TR:" .. ip .. ":N"})
    end

    -- Finally, drop the set of IPs for this account
    table.insert(pipeline_cmds, {"del", pw_hist_ips_key})

    local _, pipe_err = nauthilus_redis.redis_pipeline(redis_handle, "write", pipeline_cmds)
    nauthilus_util.if_error_raise(pipe_err)

    return true
end

function nauthilus_run_hook(logging, session)
    local result = {}

    result.level = "info"
    result.caller = N .. ".lua"
    result.session = session

    -- Get Redis connection
    local redis_pool = "default"
    local redis_handle = nauthilus_redis.get_redis_connection(redis_pool)

    -- Get action parameter
    local action = nauthilus_http_request.get_http_query_param("action")

    if not action or action == "" then
        -- Default action is to get metrics
        action = "get_metrics"
    end

    if action == "get_metrics" then
        -- Get metrics from Redis
        local metrics = get_metrics(redis_handle)

        -- Check if we have any meaningful data
        local has_data = false
        if metrics.attempts > 0 or metrics.unique_ips > 0 or metrics.unique_users > 0 or 
           metrics.threat_level > 0 or #metrics.attacked_accounts > 0 or #metrics.blocked_regions > 0 or
           #metrics.rate_limited_ips > 0 or #metrics.captcha_accounts > 0 then
            has_data = true
        end

        result.status = "success"
        if has_data then
            result.message = "Metrics retrieved successfully"
        else
            if not metrics.warmup_complete then
                result.message = "Metrics retrieved successfully. System is in warm-up; sliding windows may not reflect steady-state yet."
            else
                result.message = "Metrics retrieved successfully, but no significant activity has been detected yet. This can be normal on low-volume systems."
            end
        end
        result.metrics = metrics
    elseif action == "reset_protection" then
        -- Reset all protection measures
        local success = reset_protection_measures(redis_handle)

        result.status = "success"
        result.message = "Protection measures reset successfully"
    elseif action == "reset_account" then
        -- Get username parameter
        local username = nauthilus_http_request.get_http_query_param("username")

        if not username or username == "" then
            result.level = "error"
            result.status = "error"
            result.message = "Missing required parameter: username"
        else
            -- Reset account
            local success, error_message = reset_account(redis_handle, username)

            if success then
                result.status = "success"
                result.message = "Account reset successfully"
                result.username = username
            else
                result.level = "error"
                result.status = "error"
                result.message = "Failed to reset account"
                result.error = error_message
            end
        end
    else
        result.level = "error"
        result.status = "error"
        result.message = "Invalid action: " .. action
    end

    if logging.log_level == "debug" or logging.log_level == "info" then
        nauthilus_util.print_result(logging, result)
    end

    return result
end
