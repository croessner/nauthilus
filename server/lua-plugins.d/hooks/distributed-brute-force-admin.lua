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

dynamic_loader("nauthilus_http_request")
local nauthilus_http_request = require("nauthilus_http_request")

dynamic_loader("nauthilus_redis")
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

    -- Get current threat level
    local threat_level = nauthilus_redis.redis_hget(redis_handle, "ntc:multilayer:global:settings", "threat_level") or "0.0"
    metrics.threat_level = tonumber(threat_level) or 0.0

    -- Get current global metrics
    local current_metrics_key = "ntc:multilayer:global:current_metrics"

    -- Get global metrics
    local attempts_str = nauthilus_redis.redis_hget(redis_handle, current_metrics_key, "attempts")
    metrics.attempts = tonumber(attempts_str) or 0

    local unique_ips_str = nauthilus_redis.redis_hget(redis_handle, current_metrics_key, "unique_ips")
    metrics.unique_ips = tonumber(unique_ips_str) or 0

    local unique_users_str = nauthilus_redis.redis_hget(redis_handle, current_metrics_key, "unique_users")
    metrics.unique_users = tonumber(unique_users_str) or 0

    local ips_per_user_str = nauthilus_redis.redis_hget(redis_handle, current_metrics_key, "ips_per_user")
    metrics.ips_per_user = tonumber(ips_per_user_str) or 0

    -- Get accounts under attack
    local attacked_accounts_key = "ntc:multilayer:distributed_attack:accounts"
    local attacked_accounts = nauthilus_redis.redis_zrange(redis_handle, attacked_accounts_key, 0, -1, "WITHSCORES")
    metrics.attacked_accounts = attacked_accounts or {}

    -- Get blocked regions
    local blocked_regions_key = "ntc:multilayer:global:blocked_regions"
    local blocked_regions = nauthilus_redis.redis_smembers(redis_handle, blocked_regions_key)
    metrics.blocked_regions = blocked_regions or {}

    -- Get rate limited IPs
    local rate_limited_ips_key = "ntc:multilayer:global:rate_limited_ips"
    local rate_limited_ips = nauthilus_redis.redis_smembers(redis_handle, rate_limited_ips_key)
    metrics.rate_limited_ips = rate_limited_ips or {}

    -- Get captcha accounts
    local captcha_accounts_key = "ntc:multilayer:global:captcha_accounts"
    local captcha_accounts = nauthilus_redis.redis_smembers(redis_handle, captcha_accounts_key)
    metrics.captcha_accounts = captcha_accounts or {}

    -- Compute warm-up diagnostics (aligned with dynamic_response.lua gating)
    local now = os.time()
    local warmup_seconds = tonumber(os.getenv("DYNAMIC_RESPONSE_WARMUP_SECONDS") or "3600")
    local warmup_min_users = tonumber(os.getenv("DYNAMIC_RESPONSE_WARMUP_MIN_USERS") or "1000")
    local warmup_min_attempts = tonumber(os.getenv("DYNAMIC_RESPONSE_WARMUP_MIN_ATTEMPTS") or "10000")

    local first_seen_key = "ntc:multilayer:bootstrap:first_seen_ts"
    local first_seen_val = nauthilus_redis.redis_get(redis_handle, first_seen_key)
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

    -- Delete blocked regions
    nauthilus_redis.redis_del(redis_handle, "ntc:multilayer:global:blocked_regions")

    -- Delete rate limited IPs
    nauthilus_redis.redis_del(redis_handle, "ntc:multilayer:global:rate_limited_ips")

    -- Delete captcha accounts
    nauthilus_redis.redis_del(redis_handle, "ntc:multilayer:global:captcha_accounts")

    return true
end

-- Helper function to reset a specific account
local function reset_account(redis_handle, username)
    if not username or username == "" then
        return false, "Username is required"
    end

    -- Remove account from attacked accounts (distributed BF)
    local attacked_accounts_key = "ntc:multilayer:distributed_attack:accounts"
    -- redis_zrem expects a table of members as the third argument
    nauthilus_redis.redis_zrem(redis_handle, attacked_accounts_key, { username })

    -- Remove account from captcha accounts (global pattern/dynamic response)
    local captcha_accounts_key = "ntc:multilayer:global:captcha_accounts"
    nauthilus_redis.redis_srem(redis_handle, captcha_accounts_key, username)

    -- Delete account-specific keys in the distributed BF namespace
    local window = 3600 -- 1 hour window
    local ip_key = "nauthilus:account:" .. username .. ":ips:" .. window
    local fail_key = "nauthilus:account:" .. username .. ":fails:" .. window

    nauthilus_redis.redis_del(redis_handle, ip_key)
    nauthilus_redis.redis_del(redis_handle, fail_key)

    -- Additionally, clear classic brute-force/pw-history state so the user can log in again
    -- These keys follow the same naming as the Go server (without custom Redis prefix)
    -- 1) Remove user from AFFECTED_ACCOUNTS
    nauthilus_redis.redis_srem(redis_handle, "AFFECTED_ACCOUNTS", username)

    -- 2) Load all IPs seen for this account and remove related PW_HIST and META keys
    local pw_hist_ips_key = "PW_HIST_IPS:" .. username
    local ips = nauthilus_redis.redis_smembers(redis_handle, pw_hist_ips_key) or {}

    for _, ip in ipairs(ips) do
        -- Per-account+IP and per-IP password history hashes
        nauthilus_redis.redis_del(redis_handle, "PW_HIST:" .. username .. ":" .. ip)
        nauthilus_redis.redis_del(redis_handle, "PW_HIST:" .. ip)
        -- Metadata about protocols/OIDC seen for this IP
        nauthilus_redis.redis_del(redis_handle, "PW_HIST_META:" .. ip)
        -- Tolerate bucket keys (bf:TR) for this IP (as used by core REST flush)
        nauthilus_redis.redis_del(redis_handle, "bf:TR:" .. ip)
        nauthilus_redis.redis_del(redis_handle, "bf:TR:" .. ip .. ":P")
        nauthilus_redis.redis_del(redis_handle, "bf:TR:" .. ip .. ":N")
    end

    -- Finally, drop the set of IPs for this account
    nauthilus_redis.redis_del(redis_handle, pw_hist_ips_key)

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
