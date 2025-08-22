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
    local window_sizes = {60, 300, 900, 3600, 86400, 604800} -- 1min, 5min, 15min, 1hour, 24h, 7d
    local request_id = request.request_id or tostring(timestamp) .. "_" .. tostring(math.random(1000000))

    -- Derive a robust username identifier (some protocols fill 'account')
    local username_value = request.username or request.account or ""

    -- Batch all per-window updates into one pipeline to reduce round trips
    local pipeline_cmds = {}
    for _, window in ipairs(window_sizes) do
        local key = "ntc:multilayer:global:auth_attempts:" .. window
        table.insert(pipeline_cmds, {"run_script", "ZAddRemExpire", {key}, {timestamp, request_id, 0, timestamp - window, window * 2}})

        local ip_key = "ntc:multilayer:global:unique_ips:" .. window
        table.insert(pipeline_cmds, {"run_script", "ZAddRemExpire", {ip_key}, {timestamp, request.client_ip, 0, timestamp - window, window * 2}})

        local user_key = "ntc:multilayer:global:unique_users:" .. window
        table.insert(pipeline_cmds, {"run_script", "ZAddRemExpire", {user_key}, {timestamp, username_value, 0, timestamp - window, window * 2}})
    end
    local _, pipe_err = nauthilus_redis.redis_pipeline(custom_pool, "write", pipeline_cmds)
    nauthilus_util.if_error_raise(pipe_err)

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

    -- Fetch window counts in a single read pipeline
    local read_cmds = {
        {"zcount", key, tostring(timestamp - window), tostring(timestamp)},
        {"zcount", ip_key, tostring(timestamp - window), tostring(timestamp)},
        {"zcount", user_key, tostring(timestamp - window), tostring(timestamp)},
    }
    local res, read_err = nauthilus_redis.redis_pipeline(custom_pool, "read", read_cmds)
    nauthilus_util.if_error_raise(read_err)

    -- Structured results
    if type(res) ~= "table" then res = {} end
    local function val(i)
        local e = res[i]
        if type(e) ~= "table" then return nil end
        if e.ok == false then return nil end
        return e.value
    end

    local attempts = tonumber(val(1) or "0") or 0
    local unique_ips = tonumber(val(2) or "0") or 0
    local unique_users = tonumber(val(3) or "0") or 0

    -- Calculate metrics
    local attempts_per_ip = attempts / math.max(unique_ips, 1)
    local attempts_per_user = attempts / math.max(unique_users, 1)
    local ips_per_user = unique_ips / math.max(unique_users, 1)

    -- Store current metrics using atomic Redis Lua script
    local current_metrics_key = "ntc:multilayer:global:current_metrics"
    local _, err_script_current = nauthilus_redis.redis_run_script(
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
    nauthilus_util.if_error_raise(err_script_current)

    -- Store historical metrics (one entry per hour)
    local hour_key = os.date("%Y-%m-%d-%H", timestamp)
    local historical_metrics_key = "ntc:multilayer:global:historical_metrics:" .. hour_key

    -- Only update once per hour to avoid overwriting using atomic Redis Lua script
    local _, err_script_historical = nauthilus_redis.redis_run_script(
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
    nauthilus_util.if_error_raise(err_script_historical)

    -- Add log
    local logs = {}
    logs.caller = N .. ".lua"
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
