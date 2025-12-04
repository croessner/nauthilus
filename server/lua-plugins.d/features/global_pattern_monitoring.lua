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

local nauthilus_redis = require("nauthilus_redis")
local nauthilus_context = require("nauthilus_context")

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

    -- Track metrics via single server-side script
    local timestamp = os.time()
    local window_sizes = {60, 300, 900, 3600, 86400, 604800} -- 1min, 5min, 15min, 1hour, 24h, 7d
    -- Use request.session directly for a stable identifier
    local request_id = tostring(request.session or "")
    local username_value = request.username or request.account or ""

    local keys = {}
    for _, w in ipairs(window_sizes) do
        table.insert(keys, "ntc:multilayer:global:auth_attempts:" .. w)
        table.insert(keys, "ntc:multilayer:global:unique_ips:" .. w)
        table.insert(keys, "ntc:multilayer:global:unique_users:" .. w)
    end
    local current_metrics_key = "ntc:multilayer:global:current_metrics"
    local hour_key = os.date("%Y-%m-%d-%H", timestamp)
    local historical_metrics_key = "ntc:multilayer:global:historical_metrics:" .. hour_key
    table.insert(keys, current_metrics_key)
    table.insert(keys, historical_metrics_key)

    local per_attempt_key = "ntc:multilayer:global:metrics:" .. timestamp
    local per_attempt_ttl = 3600

    local args = {
        timestamp,
        request_id,
        request.client_ip or "",
        username_value,
        tostring(request.authenticated or false),
        per_attempt_key,
        per_attempt_ttl,
        #window_sizes,
    }
    for _, w in ipairs(window_sizes) do table.insert(args, w) end
    table.insert(args, 3600) -- hour_window

    local gpm_res, gpm_err = nauthilus_redis.redis_run_script(custom_pool, "", "GPM_TrackAndCurrent", keys, args)
    nauthilus_util.if_error_raise(gpm_err)

    -- Parse results: {attempts, unique_ips, unique_users, attempts_per_ip, attempts_per_user, ips_per_user}
    local attempts = 0
    local unique_ips = 0
    local unique_users = 0
    local attempts_per_ip = 0
    local attempts_per_user = 0
    local ips_per_user = 0
    if type(gpm_res) == "table" then
        attempts = tonumber(gpm_res[1] or 0) or 0
        unique_ips = tonumber(gpm_res[2] or 0) or 0
        unique_users = tonumber(gpm_res[3] or 0) or 0
        attempts_per_ip = tonumber(gpm_res[4] or 0) or 0
        attempts_per_user = tonumber(gpm_res[5] or 0) or 0
        ips_per_user = tonumber(gpm_res[6] or 0) or 0
    end

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

    -- Enrich rt for downstream actions (e.g., telegram)
    do
        local rt = nauthilus_context.context_get("rt") or {}
        if type(rt) == "table" then
            rt.feature_global_pattern = true
            rt.global_pattern_info = {
                attempts = attempts,
                unique_ips = unique_ips,
                unique_users = unique_users,
                attempts_per_ip = attempts_per_ip,
                attempts_per_user = attempts_per_user,
                ips_per_user = ips_per_user,
                last_updated = timestamp,
            }
            nauthilus_context.context_set("rt", rt)
        end
    end

    return nauthilus_builtin.FEATURE_TRIGGER_NO, nauthilus_builtin.FEATURES_ABORT_NO, nauthilus_builtin.FEATURE_RESULT_OK
end
