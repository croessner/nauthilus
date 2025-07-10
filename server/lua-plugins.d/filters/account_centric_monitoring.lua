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

local N = "account_centric_monitoring"

local nauthilus_util = require("nauthilus_util")

dynamic_loader("nauthilus_redis")
local nauthilus_redis = require("nauthilus_redis")

function nauthilus_call_filter(request)
    if request.no_auth then
        return nauthilus_builtin.FILTER_TRIGGER_NO, nauthilus_builtin.FILTERS_ABORT_NO, nauthilus_builtin.FILTER_RESULT_YES
    end

    -- Get Redis connection
    local custom_pool = "default"
    local custom_pool_name =  os.getenv("CUSTOM_REDIS_POOL_NAME")
    if custom_pool_name ~= nil and  custom_pool_name ~= "" then
        local err_redis_client

        custom_pool, err_redis_client = nauthilus_redis.get_redis_connection(custom_pool_name)
        nauthilus_util.if_error_raise(err_redis_client)
    end

    -- Track account-specific authentication attempts
    local timestamp = os.time()
    local window = 3600 -- 1 hour window
    local username = request.username

    if not username or username == "" then
        return nauthilus_builtin.FILTER_TRIGGER_NO, nauthilus_builtin.FILTERS_ABORT_NO, nauthilus_builtin.FILTER_RESULT_YES
    end

    -- Track IPs that attempted to access this account using atomic Redis Lua script
    local ip_key = "ntc:multilayer:account:" .. username .. ":ips:" .. window
    local _, err_script = nauthilus_redis.redis_run_script(
            custom_pool,
        "", 
        "ZAddRemExpire", 
        {ip_key}, 
        {timestamp, request.client_ip, 0, timestamp - window, window * 2}
    )
    nauthilus_util.if_error_raise(err_script)

    -- Track failed attempts for this account using atomic Redis Lua script
    if not request.authenticated then
        local fail_key = "ntc:multilayer:account:" .. username .. ":fails:" .. window
        local fail_id = request.request_id or tostring(timestamp) .. "_" .. tostring(math.random(1000000))
        local _, err_script = nauthilus_redis.redis_run_script(
                custom_pool,
            "", 
            "ZAddRemExpire", 
            {fail_key}, 
            {timestamp, fail_id, 0, timestamp - window, window * 2}
        )
        nauthilus_util.if_error_raise(err_script)
    end

    -- Get unique IPs that attempted to access this account
    local unique_ips = nauthilus_redis.redis_zcount(custom_pool, ip_key, timestamp - window, timestamp)

    -- Get failed attempts for this account
    local fail_key = "ntc:multilayer:account:" .. username .. ":fails:" .. window
    local failed_attempts = nauthilus_redis.redis_zcount(custom_pool, fail_key, timestamp - window, timestamp)

    -- Calculate the ratio of unique IPs to failed attempts
    local ip_to_fail_ratio = 0
    if failed_attempts > 0 then
        ip_to_fail_ratio = unique_ips / failed_attempts
    end

    -- Store account metrics using atomic Redis Lua script
    local account_metrics_key = "ntc:multilayer:account:" .. username .. ":metrics"
    local _, err_script = nauthilus_redis.redis_run_script(
            custom_pool,
        "", 
        "HSetMultiExpire", 
        {account_metrics_key}, 
        {
            window * 2, -- Expire after window * 2
            "unique_ips", unique_ips,
            "failed_attempts", failed_attempts,
            "ip_to_fail_ratio", ip_to_fail_ratio,
            "last_updated", timestamp
        }
    )
    nauthilus_util.if_error_raise(err_script)

    -- If many unique IPs are trying to access a single account with few attempts per IP,
    -- this could indicate a distributed brute force attack
    local is_suspicious = false
    local threshold_unique_ips = 10
    local threshold_ip_to_fail_ratio = 0.8

    if unique_ips > threshold_unique_ips and ip_to_fail_ratio > threshold_ip_to_fail_ratio then
        is_suspicious = true

        -- Add this account to the list of accounts under distributed attack using atomic Redis Lua script
        local attacked_accounts_key = "ntc:multilayer:distributed_attack:accounts"
        local _, err_script = nauthilus_redis.redis_run_script(
                custom_pool,
            "", 
            "ZAddRemExpire", 
            {attacked_accounts_key}, 
            {timestamp, username, 0, timestamp - (24 * 3600), 24 * 3600 * 2} -- Keep for 24 hours
        )
        nauthilus_util.if_error_raise(err_script)

        -- Log the suspicious activity
        local attack_logs = {}
        attack_logs.caller = N .. ".lua"
        attack_logs.ts = nauthilus_util.get_current_timestamp()
        attack_logs.level = "warning"
        attack_logs.session = request.session
        attack_logs.message = "Potential distributed brute force attack detected"
        attack_logs.username = username
        attack_logs.unique_ips = unique_ips
        attack_logs.failed_attempts = failed_attempts
        attack_logs.ip_to_fail_ratio = ip_to_fail_ratio

        nauthilus_util.print_result({ log_format = "json" }, attack_logs)

        -- Add to custom log for monitoring
        nauthilus_builtin.custom_log_add(N .. "_attack_detected", "true")
        nauthilus_builtin.custom_log_add(N .. "_username", username)
        nauthilus_builtin.custom_log_add(N .. "_unique_ips", unique_ips)
        nauthilus_builtin.custom_log_add(N .. "_failed_attempts", failed_attempts)
        nauthilus_builtin.custom_log_add(N .. "_ip_to_fail_ratio", ip_to_fail_ratio)
    end

    -- Add log
    local logs = {}
    logs.caller = N .. ".lua"
    logs.ts = nauthilus_util.get_current_timestamp()
    logs.level = "info"
    logs.session = request.session
    logs.message = "Account metrics tracked"
    logs.username = username
    logs.unique_ips = unique_ips
    logs.failed_attempts = failed_attempts
    logs.ip_to_fail_ratio = ip_to_fail_ratio
    logs.is_suspicious = is_suspicious

    nauthilus_util.print_result({ log_format = "json" }, logs)

    return nauthilus_builtin.FILTER_TRIGGER_NO, nauthilus_builtin.FILTERS_ABORT_NO, nauthilus_builtin.FILTER_RESULT_YES
end
