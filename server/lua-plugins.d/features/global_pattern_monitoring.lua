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

local N = "global_pattern_monitoring"

local nauthilus_util = require("nauthilus_util")

dynamic_loader("nauthilus_redis")
local nauthilus_redis = require("nauthilus_redis")

function nauthilus_call_feature(request)
    if request.no_auth then
        return nauthilus_builtin.FEATURE_TRIGGER_NO, nauthilus_builtin.FEATURES_ABORT_NO, nauthilus_builtin.FEATURE_RESULT_YES
    end

    -- Get Redis connection
    local custom_pool = "default"
    local custom_pool_name =  os.getenv("CUSTOM_REDIS_POOL_NAME")
    if custom_pool_name ~= nil and  custom_pool_name ~= "" then
        local err_redis_client

        custom_pool, err_redis_client = nauthilus_redis.get_redis_connection(custom_pool_name)
        nauthilus_util.if_error_raise(err_redis_client)
    end

    -- Track global authentication metrics in sliding windows
    local timestamp = os.time()
    local window_sizes = {60, 300, 900, 3600} -- 1min, 5min, 15min, 1hour
    local request_id = request.request_id or tostring(timestamp) .. "_" .. tostring(math.random(1000000))

    for _, window in ipairs(window_sizes) do
        -- Track authentication attempts using atomic Redis Lua script
        local key = "ntc:multilayer:global:auth_attempts:" .. window
        local _, err_script = nauthilus_redis.redis_run_script(
                custom_pool,
            "", 
            "ZAddRemExpire", 
            {key}, 
            {timestamp, request_id, 0, timestamp - window, window * 2}
        )
        nauthilus_util.if_error_raise(err_script)

        -- Track unique IPs using atomic Redis Lua script
        local ip_key = "ntc:multilayer:global:unique_ips:" .. window
        local _, err_script = nauthilus_redis.redis_run_script(
                custom_pool,
            "", 
            "ZAddRemExpire", 
            {ip_key}, 
            {timestamp, request.client_ip, 0, timestamp - window, window * 2}
        )
        nauthilus_util.if_error_raise(err_script)

        -- Track unique usernames using atomic Redis Lua script
        local user_key = "ntc:multilayer:global:unique_users:" .. window
        local _, err_script = nauthilus_redis.redis_run_script(
                custom_pool,
            "", 
            "ZAddRemExpire", 
            {user_key}, 
            {timestamp, request.username, 0, timestamp - window, window * 2}
        )
        nauthilus_util.if_error_raise(err_script)
    end

    -- Store metrics for this authentication attempt using atomic Redis Lua script
    local metrics_key = "ntc:multilayer:global:metrics:" .. timestamp
    local _, err_script = nauthilus_redis.redis_run_script(
            custom_pool,
        "", 
        "HSetMultiExpire", 
        {metrics_key}, 
        {
            3600, -- Keep for 1 hour
            "client_ip", request.client_ip,
            "username", request.username,
            "timestamp", timestamp,
            "success", tostring(request.authenticated or false)
        }
    )
    nauthilus_util.if_error_raise(err_script)

    -- Calculate and store current metrics for the 1-hour window
    local window = 3600
    local key = "ntc:multilayer:global:auth_attempts:" .. window
    local ip_key = "ntc:multilayer:global:unique_ips:" .. window
    local user_key = "ntc:multilayer:global:unique_users:" .. window

    local attempts = nauthilus_redis.redis_zcount(custom_pool, key, timestamp - window, timestamp)
    local unique_ips = nauthilus_redis.redis_zcount(custom_pool, ip_key, timestamp - window, timestamp)
    local unique_users = nauthilus_redis.redis_zcount(custom_pool, user_key, timestamp - window, timestamp)

    -- Calculate metrics
    local attempts_per_ip = attempts / math.max(unique_ips, 1)
    local attempts_per_user = attempts / math.max(unique_users, 1)
    local ips_per_user = unique_ips / math.max(unique_users, 1)

    -- Store current metrics using atomic Redis Lua script
    local current_metrics_key = "ntc:multilayer:global:current_metrics"
    local _, err_script = nauthilus_redis.redis_run_script(
            custom_pool,
        "", 
        "HSetMultiExpire", 
        {current_metrics_key}, 
        {
            0, -- No expiration for current metrics
            "attempts", attempts,
            "unique_ips", unique_ips,
            "unique_users", unique_users,
            "attempts_per_ip", attempts_per_ip,
            "attempts_per_user", attempts_per_user,
            "ips_per_user", ips_per_user,
            "last_updated", timestamp
        }
    )
    nauthilus_util.if_error_raise(err_script)

    -- Store historical metrics (one entry per hour)
    local hour_key = os.date("%Y-%m-%d-%H", timestamp)
    local historical_metrics_key = "ntc:multilayer:global:historical_metrics:" .. hour_key

    -- Only update once per hour to avoid overwriting using atomic Redis Lua script
    local _, err_script = nauthilus_redis.redis_run_script(
            custom_pool,
        "", 
        "ExistsHSetMultiExpire", 
        {historical_metrics_key}, 
        {
            7 * 24 * 3600, -- Keep for 7 days
            "attempts", attempts,
            "unique_ips", unique_ips,
            "unique_users", unique_users,
            "attempts_per_ip", attempts_per_ip,
            "attempts_per_user", attempts_per_user,
            "ips_per_user", ips_per_user,
            "timestamp", timestamp
        }
    )
    nauthilus_util.if_error_raise(err_script)

    -- Add log
    local logs = {}
    logs.caller = N .. ".lua"
    logs.ts = nauthilus_util.get_current_timestamp()
    logs.session = request.session
    logs.level = "info"
    logs.message = "Global metrics tracked"
    logs.attempts = attempts
    logs.unique_ips = unique_ips
    logs.unique_users = unique_users
    logs.attempts_per_ip = attempts_per_ip
    logs.attempts_per_user = attempts_per_user
    logs.ips_per_user = ips_per_user

    nauthilus_util.print_result({ log_format = "json" }, logs)

    return nauthilus_builtin.FEATURE_TRIGGER_NO, nauthilus_builtin.FEATURES_ABORT_NO, nauthilus_builtin.FEATURE_RESULT_OK
end
