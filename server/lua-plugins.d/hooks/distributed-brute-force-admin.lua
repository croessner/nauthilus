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

-- Helper function to get metrics from Redis
local function get_metrics(redis_handle)
    local metrics = {}

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

    -- Get current settings
    local settings = nauthilus_redis.redis_hgetall(redis_handle, "ntc:multilayer:global:settings")
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
            "monitoring_mode", "false"
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

    -- Remove account from attacked accounts
    local attacked_accounts_key = "ntc:multilayer:distributed_attack:accounts"
    nauthilus_redis.redis_zrem(redis_handle, attacked_accounts_key, username)

    -- Remove account from captcha accounts
    local captcha_accounts_key = "ntc:multilayer:global:captcha_accounts"
    nauthilus_redis.redis_srem(redis_handle, captcha_accounts_key, username)

    -- Delete account-specific keys
    local window = 3600 -- 1 hour window
    local ip_key = "nauthilus:account:" .. username .. ":ips:" .. window
    local fail_key = "nauthilus:account:" .. username .. ":fails:" .. window

    nauthilus_redis.redis_del(redis_handle, ip_key)
    nauthilus_redis.redis_del(redis_handle, fail_key)

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
            result.message = "Metrics retrieved successfully, but no significant activity has been detected yet. This is normal if the system has just been set up or if there have been no authentication attempts."
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
