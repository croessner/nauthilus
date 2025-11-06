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

-- Env thresholds (defaults conservative):
--  - GPM_THRESH_UNIQ_1H default 12
--  - GPM_THRESH_UNIQ_24H default 25
--  - GPM_THRESH_UNIQ_7D default 60
--  - GPM_MIN_FAILS_24H default 8
--  - GPM_THRESH_IP_TO_FAIL_RATIO default 1.2
--  - GPM_ATTACK_TTL_SEC default 43200 (12h)
--  - CUSTOM_REDIS_POOL_NAME optional pool

function nauthilus_call_filter(request)
    if request.no_auth then
        return nauthilus_builtin.FILTER_ACCEPT, nauthilus_builtin.FILTER_RESULT_OK
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
    local windows = {3600, 86400, 604800} -- 1h, 24h, 7d windows
    local username = request.username

    if not username or username == "" then
        return nauthilus_builtin.FILTER_ACCEPT, nauthilus_builtin.FILTER_RESULT_OK
    end

    -- Read tuning thresholds from environment (with safe defaults)
    local function getenv_num(name, def)
        local v = tonumber(os.getenv(name) or "")
        if v == nil then return def end
        return v
    end
    local TH_UNIQ_1H = getenv_num("GPM_THRESH_UNIQ_1H", 12)
    local TH_UNIQ_24H = getenv_num("GPM_THRESH_UNIQ_24H", 25)
    local TH_UNIQ_7D = getenv_num("GPM_THRESH_UNIQ_7D", 60)
    local TH_FAIL_MIN_24H = getenv_num("GPM_MIN_FAILS_24H", 8)
    local TH_RATIO = getenv_num("GPM_THRESH_IP_TO_FAIL_RATIO", 1.2)
    local ATTACK_TTL_SEC = getenv_num("GPM_ATTACK_TTL_SEC", 12 * 3600)

    -- Hold per-window metrics explicitly
    local uniq_1h, uniq_24h, uniq_7d = 0, 0, 0
    local fails_1h, fails_24h, fails_7d = 0, 0, 0
    local ratio_1h, ratio_24h = 0, 0

    -- Track IPs that attempted to access this account using atomic Redis Lua script
    for _, window in ipairs(windows) do
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
        if failed_attempts and failed_attempts > 0 then
            ip_to_fail_ratio = (tonumber(unique_ips) or 0) / (tonumber(failed_attempts) or 1)
        end

        -- Map to per-window holders
        if window == 3600 then
            uniq_1h = tonumber(unique_ips) or 0
            fails_1h = tonumber(failed_attempts) or 0
            ratio_1h = tonumber(ip_to_fail_ratio) or 0
        elseif window == 86400 then
            uniq_24h = tonumber(unique_ips) or 0
            fails_24h = tonumber(failed_attempts) or 0
            ratio_24h = tonumber(ip_to_fail_ratio) or 0
        elseif window == 604800 then
            uniq_7d = tonumber(unique_ips) or 0
            fails_7d = tonumber(failed_attempts) or 0
        end

        -- Store account metrics using atomic Redis Lua script (window-specific)
        local account_metrics_key = "ntc:multilayer:account:" .. username .. ":metrics:" .. window
        local _, err_script2 = nauthilus_redis.redis_run_script(
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
        nauthilus_util.if_error_raise(err_script2)
    end

    -- Suspicion logic (aims to reduce false positives due to carrier NAT/TOR)
    -- Require short-term AND long-term signals, minimum fails, and a healthy ratio
    local ratio_ok = false
    if (fails_24h > 0 and ratio_24h >= TH_RATIO) or (fails_1h > 0 and ratio_1h >= TH_RATIO) then
        ratio_ok = true
    end

    local is_suspicious = false
    if (
        (uniq_1h >= TH_UNIQ_1H or uniq_24h >= TH_UNIQ_24H) and
        uniq_7d >= TH_UNIQ_7D and
        fails_24h >= TH_FAIL_MIN_24H and
        ratio_ok
    ) then
        is_suspicious = true

        -- Add this account to the list of accounts under distributed attack using atomic Redis Lua script
        local attacked_accounts_key = "ntc:multilayer:distributed_attack:accounts"
        local _, err_script3 = nauthilus_redis.redis_run_script(
                custom_pool,
            "", 
            "ZAddRemExpire", 
            {attacked_accounts_key}, 
            {timestamp, username, 0, timestamp - ATTACK_TTL_SEC, ATTACK_TTL_SEC * 2}
        )
        nauthilus_util.if_error_raise(err_script3)

        -- Log the suspicious activity
        local attack_logs = {}
        attack_logs.caller = N .. ".lua"
        attack_logs.level = "warning"
        attack_logs.message = "Potential distributed brute force attack detected"
        attack_logs.username = username
        attack_logs.uniq_ips_1h = uniq_1h
        attack_logs.uniq_ips_24h = uniq_24h
        attack_logs.uniq_ips_7d = uniq_7d
        attack_logs.failed_1h = fails_1h
        attack_logs.failed_24h = fails_24h
        attack_logs.failed_7d = fails_7d
        attack_logs.ratio_1h = ratio_1h
        attack_logs.ratio_24h = ratio_24h
        attack_logs.thresholds = {
            TH_UNIQ_1H = TH_UNIQ_1H,
            TH_UNIQ_24H = TH_UNIQ_24H,
            TH_UNIQ_7D = TH_UNIQ_7D,
            TH_FAIL_MIN_24H = TH_FAIL_MIN_24H,
            TH_RATIO = TH_RATIO,
            ATTACK_TTL_SEC = ATTACK_TTL_SEC,
        }

        nauthilus_util.print_result({ log_format = "json" }, attack_logs)

        -- Add to custom log for monitoring
        nauthilus_builtin.custom_log_add(N .. "_attack_detected", "true")
        nauthilus_builtin.custom_log_add(N .. "_username", username)
        nauthilus_builtin.custom_log_add(N .. "_uniq_ips_1h", uniq_1h)
        nauthilus_builtin.custom_log_add(N .. "_uniq_ips_24h", uniq_24h)
        nauthilus_builtin.custom_log_add(N .. "_uniq_ips_7d", uniq_7d)
        nauthilus_builtin.custom_log_add(N .. "_failed_24h", fails_24h)
        nauthilus_builtin.custom_log_add(N .. "_ratio_24h", ratio_24h)
    end

    -- Add log with per-window metrics
    local logs = {}
    logs.caller = N .. ".lua"
    logs.level = "info"
    logs.message = "Account metrics tracked"
    logs.username = username
    logs.uniq_ips_1h = uniq_1h
    logs.uniq_ips_24h = uniq_24h
    logs.uniq_ips_7d = uniq_7d
    logs.failed_1h = fails_1h
    logs.failed_24h = fails_24h
    logs.failed_7d = fails_7d
    logs.ratio_1h = ratio_1h
    logs.ratio_24h = ratio_24h
    logs.is_suspicious = is_suspicious

    nauthilus_util.print_result({ log_format = "json" }, logs)

    return nauthilus_builtin.FILTER_ACCEPT, nauthilus_builtin.FILTER_RESULT_OK
end
